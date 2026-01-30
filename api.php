<?php


if (file_exists('vendor/autoload.php')) {
    require_once 'vendor/autoload.php';
} else {
    // Retorna erro amigável se a biblioteca faltar, em vez de erro 500 mudo
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Biblioteca Google Client não instalada no servidor (vendor missing).']);
    exit;
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

header('Content-Type: application/json; charset=utf-8');
// ========== PROTEÇÃO CONTRA BLOQUEIOS HOSTINGER ==========
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *'); // Ajuste conforme necessário
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Responder OPTIONS preflight (CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

function gerarCodigoPaciente() {
    // Gera 3 bytes aleatórios e converte para hex (6 caracteres)
    return strtoupper(bin2hex(random_bytes(3))); 
}

// Log de requisições para debug
error_log("📡 API chamada: action=" . ($_GET['action'] ?? 'N/A') . " | IP=" . $_SERVER['REMOTE_ADDR']);


// Validação básica de ação permitida (whitelist)
$acoesPermitidas = [
    'register', 'login', 'google-login', 'save-caregiver-profile',
    'create-patient-profile', 'get-patients-by-caregiver', 
    'select-patient-by-code',
    "select-patient-by-id",
     'get-caregiver-profile',
    'get-caregiver-chat', 'send-caregiver-message',
    'save-drugs', 'criar-agenda-medicamentos', 
    'buscar-agenda-medicamentos', 'atualizar-status-agenda',
    'salvar-observacao-agenda', 'atualizar-status-agenda-com-observacao',
    'update-survival-probability', // *** NOVA AÇÃO ADICIONADA AQUI ***
    'save-diary-entry', // *** NOVO ***
    'ocr-analyze-document',
    'save-sinais-vitais-exames',
    'update-caregiver-location', // <<< NOVO
    'get-caregiver-chat-geo',     // <<< NOVO
    'save-physical-measurements', // <<< ADICIONE ESTA LINHA
    'update-notification-status',
    'update-patient-profile', // Para editar doença e alergias
    'upload-avatar',
    'save-appointment',            // Criar novo agendamento
    'get-appointments',          // Buscar agendamentos (linha do tempo)
    'update-appointment-status',  // Atualizar status (Realizado, Cancelado, etc.)
    'get-patient-data',
    'save-caregiver-wellness', 
    'get-nutrition-data',
    'get-pharmacy-data',
    'get-exams-data',
    'get-procedures-data',
    'get-achievements-data',
    'get-physical-measurements',
    'get-hydric-balance',
    'get-meal-balance',
    'get-medication-summary',
    'get-medication-compliance',
    'check-ddi',
    'registrar-inicio-infusao',
    'buscar-infusoes-ativas',
    'get-gamification-data',
    'check-due-notifications',
    'update-patient-location',
    'get-last-location',
    'log-emergency',
    'save-history',
    'get-history',
    'create-decision',
    'get-decisions',
    'vote-decision',
    'invite-member',
    'update-disease-journey',
    'get-patient-details',
    'add-decision-option',
    'get-emergency-logs',
    'attempt-cancel',
    'get-premium-status',
    'start-premium-trial',
    'create-pix-payment',
    'check-payment-status',
    'reschedule-appointment',
    'update-patient-meta',
    'delete-account',
    'request-password-reset',
    'reset-password-confirm',
    'check-unread-messages',
    'finance-add-expense',
    'finance-get-initial-data',
    'finance-get-pending-items',
    'finance-get-report',
    'abandon-patient',
    'finance-get-checklist',
    'finance-toggle-benefit',
    'register-professional' ,
    'search-professional',
    'delete-decision',
    'gemini-chat', 
    'search-drugs',
    'create-card-payment',
    'plan-cancel',
    'finance-get-report-complete',
    'shift-start',
    'shift-end',
    'shift-get-report',
    'get-catheters',
    'save-catheter',
    'remove-catheter',
    'log-catheter-maintenance',
    'save-checklist',
    'verify-email',
    'contact-support',
    'get-notification-status',
    'save-attendance-report',
    'get-historico-profissionais',
    'get-price-preview',
    'get-caregiver-relation',
    'log-share',
    'get-caregiver-wellness'
];

$action = $_GET['action'] ?? null;

if (!$action || !in_array($action, $acoesPermitidas)) {
    http_response_code(400);
    echo json_encode([
        'success' => false, 
        'message' => 'Ação inválida ou não especificada.',
        'action_received' => $action
    ]);
    exit;
}


/*
  api.php - endpoints básicos para:
  - register, login, google-login
  - save-caregiver-profile
  - create-patient-profile
  - get-patients-by-caregiver
  - select-patient-by-code
  - get-caregiver-profile
  - get-caregiver-chat
  - send-caregiver-message
*/

/* -------- CONFIG - ajuste abaixo -------- */
define('DB_HOST','localhost');
define('DB_NAME','u610916991_Curadores');
define('DB_USER','u610916991_Guide2SurviveC');
define('DB_PASS','Cur@2025Guide2SurviveC@ncer'); // coloque senha

define('DB_MED_HOST', 'localhost'); // Geralmente localhost se estiver no mesmo servidor
define('DB_MED_NAME', 'u610916991_medicamentos');
define('DB_MED_USER', 'u610916991_Guide2SurviveM');
// Defina a senha aqui. Se for a mesma do banco principal, use DB_PASS
define('DB_MED_PASS', 'cur@An@2025');

define('GOOGLE_CLIENT_ID','946499185027-oa899ofai134c3uvo5pslbhjo0vrf9cj.apps.googleusercontent.com'); // para verificação (opcional)    958-705-1829
define('GEMINI_API_KEY', 'AIzaSyC8KkQ9E9oa9jkeyJHt-7wGFJaLWWJpW90'); // Sua chave real
define('GEMINI_MODEL', 'gemini-2.0-flash-exp'); // Modelo com suporte a visão   gemini-2.0-flash-exp
// Adicione estas linhas no bloco de CONFIG (substitua chaves quando disponível)
define('DRUGBANK_API_KEY', 'SEU_DRUGBANK_API_KEY_AQUI'); // coloque sua chave DrugBank
define('DRUGBANK_BASE', 'https://api.drugbank.com/v1'); // base (ajuste se necessário)
// tradução
define('GOOGLE_TRANSLATE_KEY', ''); // opcional: chave Google Translate v2 (se quiser tradução automática)
define('LIBRETRANSLATE_URL', 'https://libretranslate.de/translate'); // ou outra instância confiável
// Se quiser, pode desativar Google e usar só LibreTranslate
//Mercado pago
define ('MP_PUBLIC_KEY', 'APP_USR-618b060a-76b4-4ade-857c-fe0f081e96ae'); //teste: TEST-9aa36b6f-5471-4a27-bbc3-288284ebaebb
define ('MP_ACCESS_TOKEN', 'APP_USR-8687905913476738-120914-1eb60c3ba112682263450aec6574baef-146337664');   //teste: TEST-8687905913476738-120914-8cb90441cc6c7c5b4838ca1615f7a69b-146337664      

//URL do APP:
$URL_APP = 'https://acura.vc/'; //trocar quando tiver um url definitivo

/* ---------------------------------------- */

try {
    $pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);

    // --- CONFIGURAÇÃO DE FUSO HORÁRIO DINÂMICA ---

    // 1. Define um fuso padrão caso o cliente não envie nada
    $timezone = 'America/Sao_Paulo';

    // 2. Tenta capturar o fuso enviado pelo Frontend via Headers
    if (isset($_SERVER['HTTP_X_TIMEZONE']) && !empty($_SERVER['HTTP_X_TIMEZONE'])) {
        // Valida se é um timezone válido para evitar injeção de código ou erros
        if (in_array($_SERVER['HTTP_X_TIMEZONE'], DateTimeZone::listIdentifiers())) {
            $timezone = $_SERVER['HTTP_X_TIMEZONE'];
        }
    }

    // 3. Configura o PHP
    date_default_timezone_set($timezone);

    // 4. Configura o MySQL para alinhar com o PHP
    // Isso é CRUCIAL: calcula o offset (ex: '-03:00') baseado no timezone do PHP
    // e força o MySQL a usar esse mesmo deslocamento para esta sessão.
    try {
        $now = new DateTime();
        $mins = $now->getOffset() / 60;
        $sgn = ($mins < 0 ? -1 : 1);
        $mins = abs($mins);
        $hrs = floor($mins / 60);
        $mins -= $hrs * 60;
        $offset = sprintf('%+d:%02d', $hrs * $sgn, $mins);
        
        // Executa o comando SET time_zone logo após conectar
        // (Assumindo que $pdo é sua conexão criada anteriormente ou logo abaixo)
        if (isset($pdo)) {
            $pdo->exec("SET time_zone = '$offset'");
        }
    } catch (Exception $e) {
        error_log("Erro ao sincronizar relógio MySQL: " . $e->getMessage());
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success'=>false,'message'=>'Erro conexão DB: '.$e->getMessage() ]);
    exit;
}



$action = $_GET['action'] ?? null;
$input = json_decode(file_get_contents('php://input'), true) ?? [];

/* helper */
function json($data) { echo json_encode($data); exit; }
function fetchRow($stmt) { $r = $stmt->fetch(PDO::FETCH_ASSOC); return $r ?: null; }

/* ========== Actions ========== */

if ($action === 'register') {
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    $nome = trim($input['name'] ?? 'Usuário');

    if (!$email || !$password) {
        json(['success' => false, 'message' => 'Email e senha requeridos.']);
    }

    // Verifica se já existe
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    if ($stmt->fetch()) {
        json(['success' => false, 'message' => 'Email já cadastrado.']);
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    // Gera um token único para validação
    $tokenVerificacao = bin2hex(random_bytes(32)); 

    // Insere o usuário com o token e SEM data de verificação
    $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, verification_token, created_at) VALUES (:email, :hash, :token, NOW())");
    
    try {
        if ($stmt->execute([':email' => $email, ':hash' => $hash, ':token' => $tokenVerificacao])) {
            
            // --- ENVIO DO E-MAIL DE CONFIRMAÇÃO ---
            $linkConfirmacao = $URL_APP;
            $linkConfirmacao .="api.php?action=verify-email&token=" . $tokenVerificacao;
            // OBS: Se estiver em localhost, use: "http://localhost/seuprojeto/api.php?..."

            $titulo = "Confirme seu E-mail";
            $msg = "Olá, <b>" . htmlspecialchars($nome) . "</b>.<br><br>" .
                   "Obrigado por se cadastrar. Para garantir a segurança dos seus dados e ativar sua conta, " .
                   "por favor confirme seu endereço de e-mail clicando no botão abaixo.";
            
            $html = gerarTemplateEmail($titulo, $msg, "Confirmar E-mail", $linkConfirmacao);

            // Tenta enviar o e-mail
            if (enviarEmailSistema($email, $nome, "Confirmação de Cadastro", $html)) {
                json(['success' => true, 'message' => 'Cadastro realizado! Verifique seu e-mail para ativar a conta.']);
            } else {
                // Se o e-mail falhar, deletamos o usuário para ele tentar de novo (opcional, mas recomendado)
                $pdo->prepare("DELETE FROM users WHERE email = ?")->execute([$email]);
                json(['success' => false, 'message' => 'Erro ao enviar e-mail de confirmação. Tente novamente.']);
            }

        } else {
            json(['success' => false, 'message' => 'Erro ao criar conta.']);
        }
    } catch (PDOException $e) {
        json(['success' => false, 'message' => 'Erro SQL: ' . $e->getMessage()]);
    }
}

if ($action === 'verify-email') {
    $token = $_GET['token'] ?? '';

    if (!$token) die('Token inválido.');

    try {
        // 1. Busca e valida o usuário
        $stmt = $pdo->prepare("SELECT id, email, nickname FROM users WHERE verification_token = :token AND email_verified_at IS NULL");
        $stmt->execute([':token' => $token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $userId = $user['id'];
            $userEmail = $user['email'];

            // Extrair parte do email antes do @
            $nickname = explode('@', $userEmail)[0];
            $nickname = substr(trim($nickname), 0, 10); // Limita a 10 chars

            // 2. Ativa o usuário
            $pdo->beginTransaction();

            $update = $pdo->prepare("UPDATE users SET email_verified_at = NOW(), verification_token = NULL, nickname = :nickname WHERE id = :id");
            $update->execute([
                ':id' => $userId,
                ':nickname' => $nickname
            ]);

            // --- LÓGICA DE CONVITES PENDENTES ---
            
            // Busca se há convites para este e-mail
            $stmtCheckInvites = $pdo->prepare("SELECT id, patient_id FROM pending_invites WHERE email = :email");
            $stmtCheckInvites->execute([':email' => $userEmail]);
            $convites = $stmtCheckInvites->fetchAll(PDO::FETCH_ASSOC);

            if (count($convites) > 0) {
                // Prepara a inserção na tabela real de cuidadores
                $stmtInsertCaregiver = $pdo->prepare("
                    INSERT IGNORE INTO patient_caregivers (patient_id, caregiver_id, nickname) 
                    VALUES (:pid, :uid, 'Convidado')
                ");
                
                // Prepara a remoção da tabela de pendentes
                $stmtDeleteInvite = $pdo->prepare("DELETE FROM pending_invites WHERE id = :id");

                foreach ($convites as $convite) {
                    // Adiciona o usuário ao paciente
                    $stmtInsertCaregiver->execute([
                        ':pid' => $convite['patient_id'],
                        ':uid' => $userId
                    ]);
                    
                    // Remove o convite pendente
                    $stmtDeleteInvite->execute([':id' => $convite['id']]);
                }
            }
            // -------------------------------------

            $pdo->commit();

            // Redireciona
            header("Location: index.html?msg=verified_and_linked");
            exit;
        } else {
            echo "Link inválido ou já utilizado.";
        }
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        echo "Erro no sistema: " . $e->getMessage();
    }
    exit;
}

/* login local */
if ($action === 'login') {
    $email = trim($input['email'] ?? '');
    $password = $input['password'] ?? '';
    
    if (!$email || !$password) json(['success'=>false,'message'=>'Email e senha requeridos.']);    
    
    // 1. Busca dados básicos do usuário
    // ALTERAÇÃO AQUI: Adicionado o campo 'email_verified_at' na seleção
    $stmt = $pdo->prepare("
        SELECT id, password_hash, email_verified_at, nickname, relation, 
               appLanguage, alarmSound, measurementUnit, dataCollectionActive, 
               appFontSize, avatarUrl, is_premium 
        FROM users 
        WHERE email = :email LIMIT 1
    ");
    $stmt->execute([':email'=>$email]);
    $user = fetchRow($stmt); // Supondo que você tenha essa função auxiliar, ou use $stmt->fetch(PDO::FETCH_ASSOC)
    
    if (!$user) json(['success'=>false,'message'=>'Usuário não encontrado.']);
    
    // Verifica a senha primeiro
    if (!password_verify($password, $user['password_hash'])) {
        json(['success'=>false,'message'=>'Senha incorreta.']);
    }

    // --- NOVA TRAVA DE SEGURANÇA: VERIFICAÇÃO DE E-MAIL ---
    // Se o campo for NULL, o usuário ainda não clicou no link do e-mail
    if ($user['email_verified_at'] === null) {
        json([
            'success' => false,
            'message' => 'Conta não ativada. Por favor, verifique seu e-mail (e a pasta de spam) para confirmar seu cadastro antes de entrar.'
        ]);
        exit;
    }
    // -----------------------------------------------------
    
    // ---------------------------------------------------------
    // CORREÇÃO CRÍTICA: VERIFICAÇÃO REAL DE ASSINATURA
    // ---------------------------------------------------------
    $stmtSub = $pdo->prepare("
        SELECT status, trial_end_date 
        FROM subscriptions 
        WHERE user_id = :uid 
        ORDER BY id DESC LIMIT 1
    ");
    $stmtSub->execute([':uid' => $user['id']]);
    $sub = $stmtSub->fetch(PDO::FETCH_ASSOC);

    $isPremiumReal = false;

    if ($sub) {
        // Se o status for 'active' (pago), é premium.
        if ($sub['status'] === 'active') {
            $isPremiumReal = true;
        } 
        // Se for 'trial', verificamos se a data de hoje é ANTERIOR ao fim do trial.
        elseif ($sub['status'] === 'trial') {
            $hoje = new DateTime();
            $fimTrial = new DateTime($sub['trial_end_date']);
            if ($hoje < $fimTrial) {
                $isPremiumReal = true;
            }
        }
    }

    // Auto-correção: Atualiza a tabela users para manter o cache correto
    $pdo->prepare("UPDATE users SET is_premium = :p WHERE id = :uid")
        ->execute([':p' => $isPremiumReal ? 1 : 0, ':uid' => $user['id']]);

    // Retorno dos dados
    json(['success'=>true,'data'=>[
        'userId'=>$user['id'], 
        'nickname'=>$user['nickname'], 
        'relation'=>$user['relation'],
        'appLanguage' => $user['appLanguage'],
        'alarmSound' => $user['alarmSound'],
        'measurementUnit' => $user['measurementUnit'],
        'dataCollectionActive' => $user['dataCollectionActive'],
        'appFontSize' => $user['appFontSize'],
        'avatarUrl' => $user['avatarUrl'],
        'isPremium' => $isPremiumReal
    ]]);
}

/* google-login: recebe id_token do cliente e cria/retorna usuário.
   Recomenda-se verificar token com Google tokeninfo ou com Google client lib.
*/
if ($action === 'google-login') {
    try {
        // Recebe o JSON enviado pelo Javascript
        $input = json_decode(file_get_contents('php://input'), true);
        $idToken = $input['credential'] ?? '';

        if (!$idToken) {
            throw new Exception("Token Google não fornecido.");
        }

        // Configura o Cliente Google
        $client = new Google_Client(['client_id' => GOOGLE_CLIENT_ID]);  // Usa a constante que você definiu
        $payload = $client->verifyIdToken($idToken);

        if ($payload) {
            $googleId = $payload['sub'];
            $email = $payload['email'];
            $nome = $payload['name'];
            $foto = $payload['picture'];

            // 1. Verificar se usuário já existe
            // Nota: Adicionei IFNULL ou verificações para garantir que não venha null
            $stmt = $pdo->prepare("SELECT id, nickname, relation, 
               appLanguage, alarmSound, measurementUnit, dataCollectionActive, 
               appFontSize, avatarUrl, is_premium FROM users WHERE email = :email");  
            $stmt->execute([':email' => $email]);
            $dbUser = $stmt->fetch(PDO::FETCH_ASSOC);

            $responseData = [];

            if ($dbUser) {
                // --- CENÁRIO 1: USUÁRIO EXISTE ---
                // Usamos os dados do banco de dados (que contém as configurações salvas)
                
                // Atualiza a foto do Google se o usuário não tiver uma personalizada no banco (Opcional)
                if (empty($dbUser['avatarUrl'])) {
                     $dbUser['avatarUrl'] = $foto;
                     // Aqui você poderia fazer um UPDATE no banco se quisesse persistir a foto nova
                }

                $responseData = $dbUser; // Pega tudo que veio do SELECT
                
                // Garante mapeamento correto de nomes se o banco estiver diferente do JS
                $responseData['nome'] = $dbUser['nickname']; 
                $responseData['isPremium'] = $dbUser['is_premium']; // JS espera isPremium (camelCase)

            } else {
                // --- CENÁRIO 2: USUÁRIO NOVO ---
                // Registra e prepara os dados padrão para retorno imediato
                
                $stmt = $pdo->prepare("INSERT INTO users (nickname, email, google_id, avatarURL, data_criacao) VALUES (:nome, :email, :gid, :foto, NOW())");
                $stmt->execute([
                    ':nome' => $nome,
                    ':email' => $email,
                    ':gid' => $googleId,
                    ':foto' => $foto
                ]);
                $userId = $pdo->lastInsertId();

                // Monta o objeto de resposta com padrões (já que o banco está vazio para configs)
                $responseData = [
                    'id' => $userId,
                    'nickname' => $nome,
                    'nome' => $nome,
                    'email' => $email,
                    'avatarUrl' => $foto, // Importante: chave 'avatarUrl' para o JS
                    'relation' => '',
                    'appLanguage' => 'pt-br',       // Valor padrão
                    'alarmSound' => 'padrao',       // Valor padrão
                    'measurementUnit' => 'metric',  // Valor padrão
                    'dataCollectionActive' => 'true',
                    'appFontSize' => '16',
                    'isPremium' => false
                ];
            }

            // Iniciar sessão PHP
            if (session_status() === PHP_SESSION_NONE) session_start();
            $_SESSION['user_id'] = $responseData['id'];

            // RETORNO CORRIGIDO
            echo json_encode([
                'success' => true,
                'message' => 'Login realizado com sucesso',
                'user' => $responseData // Agora enviamos o objeto completo (do banco ou o novo)
            ]);

        } else {
            throw new Exception("Token Google inválido.");
        }

    } catch (Exception $e) {
        http_response_code(400); // Bad Request
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit; // Importante para não rodar código abaixo
}

/* salvar perfil cuidador */
if ($action === 'save-caregiver-profile') {
    $userId = $input['userId'] ?? null;
    $patientID = $input['patientID'] ?? null;
    $nickname = trim($input['nickname'] ?? '');    
    $relation = trim($input['relation'] ?? ''); //patientID

    if (!$userId || !$nickname) json(['success'=>false,'message'=>'userId e nickname requeridos.']);   
    
    // VARIÁVEIS DE CONFIGURAÇÃO DO SISTEMA
    $appLanguage = $input['appLanguage'] ?? 'pt'; // Define um default se não vier
    $alarmSound = $input['alarmSound'] ?? 'synth'; // Define um default se não vier
    $measurementUnit = $input['measurementUnit'] ?? 'metric'; // Define um default se não vier
    $dataCollectionActive = $input['dataCollectionActive'] ?? 'true'; // Define um default se não vier
    $appFontSize = $input['appFontSize'] ?? 16; // Define um default se não vier

    // Converte 'true'/'false' para 1/0 para o banco de dados
    $dataCollectionInt = (strtolower($dataCollectionActive) === 'true' || $dataCollectionActive === 1) ? 1 : 0;    
    
    // CORREÇÃO: Query simplificada para garantir a atualização
    try {

         // NOVO: Adiciona a coluna relation no UPDATE
        if($patientID){
            $stmt = $pdo->prepare("UPDATE patient_caregivers SET relationToCaregiver = :relation WHERE caregiver_id = :id AND patient_id = :idp"); 
            $stmt->execute([':relation'=>$relation, ':id'=>$userId, ':idp'=>$patientID]);
        }   

        $stmt = $pdo->prepare("
            UPDATE users 
            SET nickname = :nick, 
                relation = :relation,
                appLanguage = :appLanguage, 
                alarmSound = :alarmSound,
                measurementUnit = :measurementUnit,
                dataCollectionActive = :dataCollectionActive,
                appFontSize = :appFontSize
            WHERE id = :id
        ");
        
        $stmt->execute([
            ':nick'=>$nickname, 
            ':relation'=>$relation, 
            ':appLanguage' => $appLanguage,
            ':alarmSound' => $alarmSound,
            ':measurementUnit' => $measurementUnit,
            ':dataCollectionActive' => $dataCollectionInt, 
            ':appFontSize' => (int)$appFontSize, // Garante que o tamanho da fonte seja um INT
            ':id'=>$userId
        ]);
        
        // Adicionando log para confirmação
        error_log("✅ Configurações do Cuidador ID $userId salvas com sucesso.");
        
        json(['success'=>true]);
        
    } catch (PDOException $e) {
        // Loga e retorna o erro real do banco de dados (crucial para debug)
        error_log("❌ ERRO PDO (save-caregiver-profile): " . $e->getMessage());
        json(['success'=>false, 'message'=>'Falha ao salvar no banco de dados.']);
    }
}

/* criar paciente */
if ($action === 'create-patient-profile') {
    
    //patientDob
    
    $caregiverId = $input['caregiverId'] ?? null;
    $nickname = trim($input['nickname'] ?? '');
    $illness = trim($input['illness'] ?? '');
    
    // GERA O CÓDIGO SEGURO
    $codigoAcesso = gerarCodigoPaciente();
    
    if (!$caregiverId || !$nickname || !$illness) json(['success'=>false,'message'=>'Campos obrigatórios ausentes.']);
    $stmt = $pdo->prepare("INSERT INTO patients (nickname, illness, weight, height, gender, allergies, created_by_user_id, birth_date,codigo_acesso, created_at) VALUES (:nickname, :illness, :weight, :height, :gender, :allergies, :created_by, :patientDob, :codigo, NOW())");
    $stmt->execute([
      ':nickname'=>$nickname,
      ':illness'=>$illness,
      ':weight'=> $input['weight'] ?? null,
      ':height'=> $input['height'] ?? null,
      ':gender'=> $input['gender'] ?? null,
      ':allergies'=> $input['allergies'] ?? null,
      ':created_by'=>$caregiverId,
      ':patientDob'=>$input['patientDob']?? null,
      ':codigo' => $codigoAcesso
    ]);
    $pid = $pdo->lastInsertId();
    // adiciona pivot patient_caregivers
    $stmt = $pdo->prepare("INSERT IGNORE INTO patient_caregivers (patient_id, caregiver_id, nickname) VALUES (:pid, :cid, :nick)");
    $stmt->execute([':pid'=>$pid, ':cid'=>$caregiverId, ':nick'=> $input['caregiverNickname'] ?? '']);
    json(['success'=>true,'data'=>['patientId'=>$pid,'codigoAcesso' => $codigoAcesso]]);
            
}

/* Ação: Atualizar qual Meta é exibida (Cura, Conforto, etc) */
if ($action === 'update-patient-meta') {
    $patientId = $input['patient_id'] ?? null;
    $metaDisplay = $input['meta_display'] ?? null;

    if (!$patientId || !$metaDisplay) {
        json(['success' => false, 'message' => 'Dados inválidos.']);
    }

    try {
        $stmt = $pdo->prepare("UPDATE patients SET meta_display = :meta WHERE id = :id");
        $stmt->execute([':meta' => $metaDisplay, ':id' => $patientId]);
        
        json(['success' => true, 'message' => 'Meta atualizada com sucesso.']);
    } catch (PDOException $e) {
        json(['success' => false, 'message' => 'Erro ao salvar preferência.']);
    }
}

/* get patients by caregiver */
// 3. Listar Pacientes do Cuidador (CORRIGIDO)
if ($action === 'get-patients-by-caregiver') {
    // 1. Obtenção Segura do ID
    $caregiverId = $_GET['caregiver_id'] ?? $_GET['caregiverId'] ?? $input['caregiver_id'] ?? $_SESSION['user_id'] ?? null;

    if (!$caregiverId) {
        echo json_encode(['success' => false, 'message' => 'ID do cuidador não fornecido.']);
        exit;
    }

    try {
        // 2. A SUA QUERY ORIGINAL (Restaurada)
        // Mantivemos a estrutura exata que você informou que funciona
        $sql = "
            SELECT 
                p.id, 
                p.nickname, 
                p.illness, 
                p.weight, 
                p.height, 
                p.gender, 
                p.allergies, 
                p.avatarUrl, -- Adicionei caso exista, senão o JS trata
                p.Notification, -- Coluna direta da tabela patients
                CASE 
                    WHEN EXISTS (
                        SELECT 1 FROM decisions d 
                        WHERE d.patient_id = p.id 
                        AND d.deadline > NOW()
                    ) THEN 1 
                    ELSE 0 
                END as has_active_vote
            FROM patients p
            JOIN patient_caregivers cp ON p.id = cp.patient_id
            WHERE cp.caregiver_id = :cid
            ORDER BY p.nickname ASC
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':cid' => $caregiverId]);
        $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // 3. Preparação dos dados para o Front
        $finalData = [];
        foreach ($patients as $pt) {
            // Garante tipagem correta para o Javascript
            // Nota: Usamos $pt['Notification'] (com N maiúsculo) pois é assim que vem do banco
            $pt['Notification'] = ($pt['Notification'] == 1 || $pt['Notification'] == '1') ? 1 : 0;
            $pt['has_active_vote'] = ($pt['has_active_vote'] == 1) ? 1 : 0;
            $finalData[] = $pt;
        }

        echo json_encode(['success' => true, 'data' => $finalData]);

    } catch (PDOException $e) {
        error_log("Erro SQL em get-patients: " . $e->getMessage());
        http_response_code(500);
        // Em produção, evite mostrar o erro SQL exato, mas para seu debug agora:
        echo json_encode(['success' => false, 'message' => 'Erro SQL: ' . $e->getMessage()]);
    }
    exit;
}

// api.php

elseif ($action === 'get-caregiver-relation') {
    $caregiverId = $_GET['caregiverId'] ?? null;
    $patientId = $_GET['patientId'] ?? null;

    if (!$caregiverId || !$patientId) {
        echo json_encode(['success' => false, 'message' => 'IDs do cuidador e do paciente são obrigatórios.']);
        exit;
    }

    try {
        // Busca apenas o campo relationToCaregiver na tabela de vínculo
        $stmt = $pdo->prepare("
            SELECT relationToCaregiver 
            FROM patient_caregivers 
            WHERE caregiver_id = :cid AND patient_id = :pid 
            LIMIT 1
        ");
        
        $stmt->execute([':cid' => $caregiverId, ':pid' => $patientId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            // Retorna o dado (pode vir nulo se não tiver sido definido ainda)
            echo json_encode([
                'success' => true, 
                'relation' => $result['relationToCaregiver'] ?? '' 
            ]);
        } else {
            // Caso raro: Cuidador acessando paciente sem vínculo na tabela
            echo json_encode(['success' => false, 'message' => 'Vínculo não encontrado.']);
        }

    } catch (PDOException $e) {
        error_log("Erro ao buscar relação: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Erro interno ao buscar dados.']);
    }
    exit;
}

/* select patient by code (id) - returns patient info and registers caregiver->patient relation */
if ($action === 'select-patient-by-id') {
    $patientId = $input['patientId'] ?? null;
    $caregiverId = $input['caregiverId'] ?? null;
    $caregiverNick = $input['caregiverNickname'] ?? '';
    if (!$patientId || !$caregiverId) json(['success'=>false,'message'=>'patientId e caregiverId requeridos.']);
    // verify patient exists
    // *** MODIFICADO: Selecionar survivalProbability aqui ***
    $stmt = $pdo->prepare("SELECT *, COALESCE(survivalProbability, 100.00) as survivalProbability, tasksCompleted, taskProgress, allergies, avatarUrl, updated_at, weight, height, gender, birth_date, Notification, meta_display, codigo_acesso FROM patients WHERE id = :id LIMIT 1");
    $stmt->execute([':id'=>$patientId]);
    $patient = fetchRow($stmt);
    if (!$patient) json(['success'=>false,'message'=>'Paciente não encontrado.']);
    
    // 2. Lógica de Reset Diário
        $today = new DateTime('today');
        // Converte o updated_at do banco (timestamp/datetime) para um objeto DateTime
        $lastUpdate = new DateTime($patient['updated_at']);

        // Se a última atualização foi ANTES de hoje, precisamos zerar o progresso
        if ($lastUpdate < $today) {
            $patientId = $patient['paciente_id'];
            
            // Zerar tasksCompleted e taskProgress no banco de dados
            $updateSql = "UPDATE patients SET taskProgress = 0, tasksCompleted = 0 WHERE id = :id";
            $updateStmt = $pdo->prepare($updateSql);
            $updateStmt->execute([':id' => $patientId]);

            // Atualizar o objeto paciente retornado para o frontend
            $patient['taskProgress'] = 0;
            $patient['tasksCompleted'] = 0;
            $patient['updated_at'] = date('Y-m-d H:i:s'); // Opcional: refletir que foi "atualizado" agora

            error_log("✅ Progresso diário resetado para o paciente ID: " . $patientId);
        }
    
    // insert pivot if not exists
    $stmt = $pdo->prepare("INSERT IGNORE INTO patient_caregivers (patient_id, caregiver_id, nickname) VALUES (:pid, :cid, :nick)");
    $stmt->execute([':pid'=>$patientId, ':cid'=>$caregiverId, ':nick'=>$caregiverNick]);
    // return patient
    json(['success'=>true,'data'=>$patient]);
}

if ($action === 'select-patient-by-code') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // 1. Recebe o código alfanumérico e o ID do cuidador
    $codigoDigitado = trim($input['code'] ?? '');
    $caregiverId = $input['caregiverId'] ?? null;
    $caregiverNick = $input['caregiverNickname'] ?? '';
    
    
    if (!$codigoDigitado || !$caregiverId) {
        json(['success' => false, 'message' => 'Código de acesso e Caregiver ID são obrigatórios.']);
    }

    // 2. Busca o paciente pelo ACCESS_CODE na tabela 'patients'
    // Mantive todos os seus campos e a lógica do COALESCE
    $sql = "SELECT *, 
            COALESCE(survivalProbability, 100.00) as survivalProbability, 
            tasksCompleted, 
            taskProgress, 
            allergies, 
            avatarUrl, 
            updated_at, 
            weight, 
            height, 
            gender, 
            birth_date,
            Notification, 
            meta_display 
            FROM patients 
            WHERE codigo_acesso = :code 
            LIMIT 1";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':code' => $codigoDigitado]);
    $patient = fetchRow($stmt); // Usando sua função helper fetchRow se disponível, ou $stmt->fetch(PDO::FETCH_ASSOC)

    if (!$patient) {
        json(['success' => false, 'message' => 'Paciente não encontrado com este código.']);
    }

    $patientId = $patient['id'];

    // 3. Lógica de Reset Diário (Mantida igual ao seu original)
    $today = new DateTime('today');
    $lastUpdateStr = $patient['updated_at'];
    $lastUpdate = $lastUpdateStr ? new DateTime($lastUpdateStr) : new DateTime('2000-01-01');

    if ($lastUpdate < $today) {
        // Zera o progresso na tabela 'patients'
        $updateSql = "UPDATE patients SET taskProgress = 0, tasksCompleted = 0, updated_at = NOW() WHERE id = :id";
        $updateStmt = $pdo->prepare($updateSql);
        $updateStmt->execute([':id' => $patientId]);

        // Atualiza o array para retornar ao front
        $patient['taskProgress'] = 0;
        $patient['tasksCompleted'] = 0;
        $patient['updated_at'] = date('Y-m-d H:i:s');
        
        error_log("✅ Progresso diário resetado para o paciente ID: " . $patientId);
    }

    // 4. Cria o vínculo na tabela 'patient_caregivers' se não existir
    // Usando INSERT IGNORE como no seu código original
    $stmtLink = $pdo->prepare("INSERT IGNORE INTO patient_caregivers (patient_id, caregiver_id, nickname) VALUES (:pid, :cid, :nick)");
    $stmtLink->execute([
        ':pid' => $patientId, 
        ':cid' => $caregiverId, 
        ':nick' => $caregiverNick
    ]);

    // Retorna o paciente encontrado
    json(['success' => true, 'data' => $patient]);
}

/* get-caregiver-profile */
if ($action === 'get-caregiver-profile') {
    $userId = $_GET['userId'] ?? null;
    if (!$userId) json(['success'=>false,'message'=>'userId requerido.']);
    $stmt = $pdo->prepare("SELECT id, email, nickname, relation, created_at FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id'=>$userId]);
    $user = fetchRow($stmt);
    if (!$user) json(['success'=>false,'message'=>'Usuário não encontrado.']);
    json(['success'=>true,'data'=>$user]);
}

/* get-caregiver-chat (messages for patient) */
if ($action === 'get-caregiver-chat') {
    $patientId = $_GET['patientId'] ?? null;
    $chatChannel = $_GET['chatChannel'] ?? 'patient_group'; // PARAMETRO DE FILTRO
    
    if (!$patientId) json(['success'=>false,'message'=>'patientId requerido.']);

    // Modificado: Adicionado filtro por chat_channel
    $stmt = $pdo->prepare("
        SELECT id, patient_id, sender_id, sender_nickname, text, created_at, chat_channel 
        FROM caregiver_chat_messages 
        WHERE patient_id = :patient_id 
        AND chat_channel = :chat_channel
        ORDER BY created_at DESC 
        LIMIT 50
    ");
    
    $stmt->execute([
        ':patient_id'=>$patientId,
        ':chat_channel' => $chatChannel
    ]);
    
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    json(['success'=>true,'data'=>$rows]);
}

/* send-caregiver-message */
if ($action === 'send-caregiver-message') {
    $patientId = $input['patientId'] ?? null;
    $senderId = $input['senderId'] ?? null;
    $senderNickname = $input['senderNickname'] ?? '';
    $text = trim($input['text'] ?? '');
    // NOVO: Coleta o chatChannel enviado pelo JS
    $chatChannel = $input['chatChannel'] ?? 'patient_group'; 
    $originLocation = trim($input['originLocation'] ?? '');

    // Validação de campos obrigatórios
    if (!$patientId || !$senderId || !$text) {
        error_log("ERRO (send-caregiver-message): Campos obrigatórios ausentes.");
        json(['success'=>false,'message'=>'Campos requeridos ausentes (patientId, senderId, text).']);
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO caregiver_chat_messages (patient_id, sender_id, sender_nickname, text, chat_channel, originLocation) 
            VALUES (:pid, :sid, :sname, :text, :channel, :originLocation)
        ");

        $stmt->execute([
            ':pid' => $patientId, 
            ':sid' => $senderId, 
            ':sname' => $senderNickname, 
            ':text' => $text,
            ':channel' => $chatChannel, // NOVO: Adiciona o canal
            ':originLocation' => $originLocation // NOVO: Adiciona o canal  
        ]);

        json(['success'=>true, 'message'=>'Mensagem enviada com sucesso.']);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (send-caregiver-message): " . $e->getMessage());
        json(['success'=>false,'message'=>'Erro ao enviar mensagem (DB): '.$e->getMessage() ]);
    }
    exit;
}

if ($action === 'check-unread-messages') {
    $uid = $input['userId'] ?? null;
    $patientId = $input['patientId'] ?? null;
    $lastReadTime = $input['lastReadTime'] ?? '2000-01-01 00:00:00';

    if (!$uid) {
        json(['success' => false, 'hasUnread' => false, 'count' => 0, 'message' => 'userId required']);
    }

    try {
        // Contar mensagens que:
        //  - foram criadas após a última leitura;
        //  - não foram enviadas pelo próprio usuário;
        //  - e pertencem ao paciente atual (quando informado) OU são mensagens gerais/geo (chat_channel IS NULL ou diferente).
        // Observação: ajuste a condição de canal conforme precisar (patient_group / geo_group).
        $sql = "
            SELECT COUNT(*) AS total
            FROM caregiver_chat_messages
            WHERE created_at > :lastRead
              AND (sender_id IS NULL OR sender_id != :uid)
              AND (
                    (:pid IS NOT NULL AND patient_id = :pid)
                    OR (:pid IS NULL AND patient_id IS NULL)
                  )
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':lastRead' => $lastReadTime,
            ':uid' => $uid,
            ':pid' => $patientId
        ]);

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $count = (int)($row['total'] ?? 0);
        $hasUnread = $count > 0;

        json([
            'success' => true,
            'hasUnread' => $hasUnread,
            'count' => $count
        ]);
    } catch (Exception $e) {
        error_log("Erro check-unread-messages: " . $e->getMessage());
        json(['success' => false, 'hasUnread' => false, 'count' => 0, 'message' => 'Erro ao consultar mensagens.']);
    }
    exit;
}

/* save-drugs */ 
if ($action === 'save-drugs') {
    try {
        // Validação básica de campos obrigatórios
        $camposObrigatorios = ['paciente_id', 'nome_medicamento', 'dosagem', 'unidade_dosagem'];
        foreach ($camposObrigatorios as $campo) {
            if (empty($input[$campo])) {
                json(['success' => false, 'error' => "Campo obrigatório ausente: $campo"]);
                exit;
            }
        }
        
        // Preparar a query (corrigido: adicionado parêntese de fechamento)
        $stmt = $pdo->prepare("
        INSERT INTO medicamentos_prescritos (
            paciente_id, nome_medicamento, via_administracao, dosagem, unidade_dosagem, 
            volume_diluicao_liquido, volume_diluicao_quant, unidade_diluicao, 
            vazao_bomba, intervalo_horas, data_hora_inicio, medico_prescritor, 
            data_hora_suspensao, status_receita, status_pagador
        ) 
        SELECT 
            :paciente_id, :nome_medicamento, :via_administracao, :dosagem, :unidade_dosagem,
            :volume_diluicao_liquido, :volume_diluicao_quant, :unidade_diluicao,
            :vazao_bomba, :intervalo_horas, :data_hora_inicio, :medico_prescritor,
            :data_hora_suspensao, :status_receita, :status_pagador
        FROM (SELECT 1) AS dummy_table
        WHERE NOT EXISTS (
            SELECT 1 
            FROM medicamentos_prescritos 
            WHERE nome_medicamento = :nome_medicamento 
                AND paciente_id = :paciente_id_check 
                AND dosagem = :dosagem_check
                AND status_receita = 'Ativa'
            )
        ");
        
        // Executar a query
        $stmt->execute([
            ':paciente_id' => $input['paciente_id'] ?? null,
            ':nome_medicamento' => $input['nome_medicamento'] ?? null, 
            ':via_administracao' => $input['via_administracao'] ?? null, 
            ':dosagem' => $input['dosagem'] ?? null,  
            ':unidade_dosagem' => $input['unidade_dosagem'] ?? null, 
            ':volume_diluicao_liquido' => $input['volume_diluicao_liquido'] ?? null, 
            ':volume_diluicao_quant' => $input['volume_diluicao_quant'] ?? null, 
            ':unidade_diluicao' => $input['unidade_diluicao'] ?? null, 
            ':vazao_bomba' => $input['vazao_bomba'] ?? null,  
            ':intervalo_horas' => $input['intervalo_horas'] ?? null, 
            ':data_hora_inicio' => $input['data_hora_inicio'] ?? null,  
            ':medico_prescritor' => $input['medico_prescritor'] ?? null, 
            ':data_hora_suspensao' => empty($input['data_hora_suspensao']) ? null : $input['data_hora_suspensao'],     
            ':status_receita' => $input['status_receita'] ?? null, 
            ':status_pagador' => $input['status_pagador'] ?? null, 
            // Parâmetros para a verificação (WHERE NOT EXISTS)
            ':paciente_id_check' => $input['paciente_id'] ?? null,
            ':dosagem_check' => $input['dosagem'] ?? null,
        ]);
        
        // Obter o ID do registro inserido
        $pid = $pdo->lastInsertId();
        
        // Buscar o medicamento completo
        $stmt = $pdo->prepare("SELECT * FROM medicamentos_prescritos WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $pid]);
        
        // Fetch do medicamento (usando método nativo do PDO)
        $medicamento = $stmt->fetch(PDO::FETCH_ASSOC);
        
        
        
        // Retornar resposta de sucesso
        json([
            'success' => true, 
            'data' => [
                'id' => $pid, 
                'medicamento' => $medicamento
            ]
        ]);
                        
    } catch (PDOException $e) {
        // Tratamento de erro
        json([
            'success' => false, 
            'error' => 'Erro ao salvar medicamento: ' . $e->getMessage()
        ]);
    }
}    

/* criar-agenda-medicamentos */
if ($action === 'criar-agenda-medicamentos') {
    try {
        $pacienteId = $input['paciente_id'] ?? null;
        
        // Busca medicamentos ativos
        $sql = "SELECT * FROM medicamentos_prescritos WHERE status_receita = 'Ativa'";
        if ($pacienteId) {
            $sql .= " AND paciente_id = :paciente_id";
        }
        
        $stmt = $pdo->prepare($sql);
        if ($pacienteId) {
            $stmt->execute([':paciente_id' => $pacienteId]);
        } else {
            $stmt->execute();
        }
        
        $medicamentosAtivos = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($medicamentosAtivos)) {
            json([
                'success' => true, 
                'message' => 'Nenhum medicamento ativo encontrado.', 
                'tarefas_criadas' => 0
            ]);
            exit;
        }
        
        $tarefasCriadas = 0;
        $tarefasJaExistentes = 0;
        $erros = [];
        
        foreach ($medicamentosAtivos as $medicamento) {
            $medicamentoId = $medicamento['id'];
            $dataHoraInicio = $medicamento['data_hora_inicio'];
            
            if (empty($dataHoraInicio)) {
                $erros[] = "Medicamento ID {$medicamentoId} sem data de início.";
                continue;
            }

            // --- TRATAMENTO DO DILUENTE (SEM COLUNA EXTRA) ---
            // Como a coluna 'diluente_volume' não existe, vamos adicionar essa informação
            // ao nome do medicamento para que o cuidador não perca esse dado.
            $diluenteRaw = $medicamento['volume_diluicao_quant'] ?? '';
            $nomeFinal = $medicamento['nome_medicamento'];
            
            // Se tiver diluente e não for 'nenhum', concatena no nome
            if ($diluenteRaw && strtolower($diluenteRaw) !== 'nenhum') {
                $nomeFinal .= " (Diluição: " . $diluenteRaw . ")";
            }
            
            // Verifica duplicidade
            $stmtCheck = $pdo->prepare("
                SELECT COUNT(*) as total FROM agenda_medicamentos 
                WHERE medicamento_id = :medicamento_id AND status IS NULL
            ");
            $stmtCheck->execute([':medicamento_id' => $medicamentoId]);
            
            if ($stmtCheck->fetch(PDO::FETCH_ASSOC)['total'] > 0) {
                $tarefasJaExistentes++;
                continue;
            }
            
            // --- INSERT CORRIGIDO ---
            // 1. Removida a coluna inexistente 'diluente_volume'
            // 2. Corrigida a ordem dos campos dosagem, unidade e via
            $stmtInsert = $pdo->prepare("
                INSERT INTO agenda_medicamentos (
                    paciente_id,
                    medicamento_id,
                    nome_medicamento,
                    via_administracao,   
                    dosagem,
                    unidade_dosagem,
                    data_hora_agendada,
                    status,
                    created_at
                ) VALUES (
                    :paciente_id,
                    :medicamento_id,
                    :nome_medicamento,
                    :via_administracao,
                    :dosagem,
                    :unidade_dosagem,
                    :data_hora_agendada,
                    NULL,
                    NOW()
                )
            ");
            
            // Mapeamento explícito para evitar trocas
            $stmtInsert->execute([
                ':paciente_id'      => $medicamento['paciente_id'],
                ':medicamento_id'   => $medicamentoId,
                ':nome_medicamento' => $nomeFinal, // Nome alterado com o diluente
                ':via_administracao'=> $medicamento['via_administracao'], // Via vai para Via
                ':dosagem'          => $medicamento['dosagem'],           // Dose vai para Dose
                ':unidade_dosagem'  => $medicamento['unidade_dosagem'],   // Unidade vai para Unidade
                ':data_hora_agendada'=> $dataHoraInicio
            ]);
            
            $tarefasCriadas++;
        }
        
        json([
            'success' => true,
            'message' => 'Agenda criada/atualizada com sucesso.',
            'tarefas_criadas' => $tarefasCriadas,
            'tarefas_ja_existentes' => $tarefasJaExistentes
        ]);
        
    } catch (PDOException $e) {
        json(['success' => false, 'error' => 'Erro SQL: ' . $e->getMessage()]);
    }
}

/*Busca agenda de medicamentos*/
if ($action === 'buscar-agenda-medicamentos') {
    try {
        // Validar paciente_id
        $pacienteId = $input['paciente_id'] ?? null;
        
        if (!$pacienteId) {
            json([
                'success' => false,
                'error' => 'paciente_id é obrigatório.'
            ]);
            exit;
        }
        
        // *** NOVO: Obter data/hora do dispositivo do usuário ***
        $dataHoraDispositivo = $input['data_hora_dispositivo'] ?? null;
        $fusoHorario = $input['fuso_horario'] ?? null;
        
        // Se não foi enviado, usar horário do servidor como fallback
        if (!$dataHoraDispositivo) {
            $dataHoraDispositivo = date('Y-m-d H:i:s');
            $fusoHorario = 'UTC+00:00'; // Fallback para UTC
            error_log("⚠️ Data/hora do dispositivo não enviada. Usando horário do servidor: $dataHoraDispositivo");
        } else {
            error_log("✅ Usando data/hora do dispositivo: $dataHoraDispositivo (Fuso: $fusoHorario)");
        }
        
        // Validar formato da data/hora
        $dataHoraObj = DateTime::createFromFormat('Y-m-d H:i:s', $dataHoraDispositivo);
        if (!$dataHoraObj) {
            json([
                'success' => false,
                'error' => 'Formato de data/hora inválido. Use: YYYY-MM-DD HH:MM:SS'
            ]);
            exit;
        }
        
        // *** MODIFICADO: Usar data/hora do dispositivo na consulta ***
        $stmt = $pdo->prepare("
            SELECT 
                a.id,
                a.medicamento_id,
                a.nome_medicamento,
                a.via_administracao,
                a.dosagem,
                a.unidade_dosagem,
                a.data_hora_agendada,
                m.volume_diluicao_quant,
                m.vazao_bomba
            FROM agenda_medicamentos a
            LEFT JOIN medicamentos_prescritos m ON a.medicamento_id = m.id
            WHERE a.paciente_id = :paciente_id
            AND a.status IS NULL
            AND a.data_hora_agendada <= :data_hora_dispositivo
            ORDER BY a.data_hora_agendada ASC
        ");
        
        $stmt->execute([
            ':paciente_id' => $pacienteId,
            ':data_hora_dispositivo' => $dataHoraDispositivo
        ]);
        
        $tarefas = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Log para debug
        error_log("📋 Agenda buscada para paciente $pacienteId: " . count($tarefas) . " tarefa(s) encontrada(s)");
        error_log("⏰ Critério de busca: tarefas <= $dataHoraDispositivo");
        
        // Retornar tarefas
        json([
            'success' => true,
            'data' => [
                'tarefas' => $tarefas,
                'total' => count($tarefas),
                'paciente_id' => $pacienteId,
                'data_hora_referencia' => $dataHoraDispositivo,
                'fuso_horario' => $fusoHorario
            ]
        ]);
        
    } catch (PDOException $e) {
        error_log("❌ Erro ao buscar agenda: " . $e->getMessage());
        json([
            'success' => false,
            'error' => 'Erro ao buscar agenda: ' . $e->getMessage()
        ]);
    } catch (Exception $e) {
        error_log("❌ Erro geral ao buscar agenda: " . $e->getMessage());
        json([
            'success' => false,
            'error' => 'Erro ao processar requisição: ' . $e->getMessage()
        ]);
    }
}

/*Atualiza agenda de medicamentos*/
if ($action === 'atualizar-status-agenda') {
    try {
        $id = $input['id'] ?? null;
        $novoStatus = $input['status'] ?? null;
        $dataHoraRealizada = $input['data_hora_realizada'] ?? null;          
        $observacoes = $input['observacoes'] ?? null;
        $caregiverId = $input['caregiver_id'] ?? null;

        error_log("==== INÍCIO atualizar-status-agenda ====");
        
        if (!$id || !$novoStatus || !$dataHoraRealizada) {
            json(['success' => false, 'error' => 'Parâmetros obrigatórios ausentes.']);
            exit;
        }

        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // 1️⃣ Atualiza o registro original
        $stmtUpdate = $pdo->prepare("
            UPDATE agenda_medicamentos
            SET status = :status,
                data_hora_realizada = :data_hora_realizada,
                observacoes = COALESCE(:observacoes, observacoes),
                updated_by = :caregiverId,
                updated_at = NOW()
            WHERE id = :id
        ");
        $stmtUpdate->execute([
            ':status' => $novoStatus,
            ':data_hora_realizada' => $dataHoraRealizada,
            ':observacoes' => $observacoes, 
            ':caregiverId' => $caregiverId, 
            ':id' => $id
        ]);

        // 2️⃣ Busca medicamento_id
        $stmtMedId = $pdo->prepare("SELECT medicamento_id FROM agenda_medicamentos WHERE id = :id");
        $stmtMedId->execute([':id' => $id]);
        $medIdRow = $stmtMedId->fetch(PDO::FETCH_ASSOC);

        if (!$medIdRow) {
            json(['success' => false, 'error' => 'Registro não encontrado.']);
            exit;
        }
        $medicamentoId = $medIdRow['medicamento_id'];

        // 3️⃣ Busca regras da prescrição
        $stmtMed = $pdo->prepare("SELECT intervalo_horas, data_hora_suspensao FROM medicamentos_prescritos WHERE id = :mid");
        $stmtMed->execute([':mid' => $medicamentoId]);
        $medicamento = $stmtMed->fetch(PDO::FETCH_ASSOC);

        if (!$medicamento) {
            json(['success' => false, 'error' => 'Medicamento prescrito não encontrado.']);
            exit;
        }

        $dataRealizadaTS = strtotime($dataHoraRealizada);
        $dataSuspensaoTS = !empty($medicamento['data_hora_suspensao']) ? strtotime($medicamento['data_hora_suspensao']) : null;
        $intervaloHoras = (float) $medicamento['intervalo_horas'];

        // 4️⃣ Checa suspensão
        if (($dataSuspensaoTS && $dataRealizadaTS > $dataSuspensaoTS) || $novoStatus == "Suspensa") {
            $pdo->prepare("UPDATE medicamentos_prescritos SET status_receita = 'Suspensa', ultima_dose_tomada = :dr WHERE id = :mid")
                ->execute([':dr' => $dataHoraRealizada, ':mid' => $medicamentoId]);
            json(['success' => false, 'error' => 'Medicamento suspenso.']);
            exit;
        }

        // 5️⃣ Calcula nova data
        $novaDataHora = date('Y-m-d H:i:s', strtotime("+{$intervaloHoras} hours", $dataRealizadaTS));

        // 6️⃣ Inserir novo registro COM PROTEÇÃO DUPLA
        $stmtDup = $pdo->prepare("
            INSERT INTO agenda_medicamentos (
                paciente_id, medicamento_id, nome_medicamento, via_administracao, 
                dosagem, unidade_dosagem, data_hora_agendada, observacoes, 
                status, created_at, updated_at, origin_medicamento_id
            )
            SELECT
                origem.paciente_id, origem.medicamento_id, origem.nome_medicamento, origem.via_administracao, 
                origem.dosagem, origem.unidade_dosagem, :nova_data, NULL, NULL, NOW(), NOW(), origem.id
            FROM agenda_medicamentos AS origem
            WHERE origem.id = :id
            
            -- PROTEÇÃO 1: Impede criar filho se já existe um filho para este pai (origin_medicamento_id)
            AND NOT EXISTS (
                SELECT 1 FROM agenda_medicamentos AS filho 
                WHERE filho.origin_medicamento_id = origem.id
            )
            
            -- PROTEÇÃO 2: Impede criar se já existe agendamento igual no mesmo horário (Segurança extra)
            AND NOT EXISTS (
                SELECT 1 FROM agenda_medicamentos AS destino 
                WHERE destino.medicamento_id = origem.medicamento_id 
                AND destino.data_hora_agendada = :nova_data_check
            )
        ");

        $stmtDup->execute([
            ':nova_data'       => $novaDataHora,
            ':nova_data_check' => $novaDataHora,
            ':id'              => $id
        ]);
        
        $novoId = $pdo->lastInsertId();

        if ($novoId) {
            json(['success' => true, 'message' => 'Status atualizado e próxima dose agendada.']);
        } else {
            // Se não criou ID, é porque caiu em um dos NOT EXISTS
            json(['success' => true, 'message' => 'Status atualizado. Próxima dose já existia (evitou duplicidade).']);
        }
        exit;

    } catch (Exception $e) {
        error_log("Erro atualizar-status-agenda: " . $e->getMessage());
        json(['success' => false, 'error' => 'Erro interno: ' . $e->getMessage()]);
        exit;
    }
}   

/* Salva Apenas a Observação da Agenda */
if ($action === 'salvar-observacao-agenda') {
    try {
        $id = $input['id'] ?? null;
        $observacoes = $input['observacoes'] ?? null;

        if (!$id || $observacoes === null) {
            json(['success' => false, 'error' => 'ID ou Observação ausente.']);
            exit;
        }

        $stmtUpdate = $pdo->prepare("
            UPDATE agenda_medicamentos
            SET observacoes = :observacoes,
                updated_at = NOW()
            WHERE id = :id
        ");
        
        $stmtUpdate->execute([
            ':observacoes' => $observacoes,
            ':id' => $id
        ]);
        
        json(['success' => true, 'message' => 'Observação salva com sucesso.']);
        exit;

    } catch (Exception $e) {
        error_log("EXCEÇÃO (salvar-observacao-agenda): " . $e->getMessage());
        json(['success' => false, 'error' => 'Erro: ' . $e->getMessage()]);
        exit;
    }
}

/* Atualiza status (Ignorada/Suspensa) e salva Observações */
if ($action === 'atualizar-status-agenda-com-observacao') {
    try {
        $id = $input['id'] ?? null;
        $novoStatus = $input['status'] ?? null;
        $dataHoraRealizada = $input['data_hora_realizada'] ?? null;
        // *** NOVO: Coleta a observação ***
        $observacoes = $input['observacoes'] ?? null; 

        error_log("==== INÍCIO atualizar-status-agenda-com-observacao ====");
        error_log("Parâmetros recebidos -> ID: $id | Status: $novoStatus | DataHora: $dataHoraRealizada | Obs: $observacoes");

        if (!$id || !$novoStatus || !$dataHoraRealizada) {
            error_log("ERRO: Parâmetros obrigatórios ausentes.");
            json(['success' => false, 'error' => 'Parâmetros obrigatórios ausentes.']);
            exit;
        }

        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // 1️⃣ Atualiza o registro original
        $stmtUpdate = $pdo->prepare("
            UPDATE agenda_medicamentos
            SET status = :status,
                data_hora_realizada = :data_hora_realizada,
                -- *** NOVO: Salva a observação ***
                observacoes = :observacoes, 
                updated_at = NOW()
            WHERE id = :id
        ");
        $stmtUpdate->execute([
            ':status' => $novoStatus,
            ':data_hora_realizada' => $dataHoraRealizada,
            ':observacoes' => $observacoes, // Salva a observação
            ':id' => $id
        ]);
        error_log("Registro original ID=$id atualizado com status=$novoStatus e observação.");

        
        // 2️⃣ Lógica de Suspensão (Apenas se o status for 'Suspensa')
        if ($novoStatus === "Suspensa") {
             // Buscar medicamento_id
             $stmtMedId = $pdo->prepare("SELECT medicamento_id FROM agenda_medicamentos WHERE id = :id");
             $stmtMedId->execute([':id' => $id]);
             $medIdRow = $stmtMedId->fetch(PDO::FETCH_ASSOC);

             if ($medIdRow) {
                 $medicamentoId = $medIdRow['medicamento_id'];

                 // Atualiza a receita principal como Suspensa
                 $stmtSuspende = $pdo->prepare("
                     UPDATE medicamentos_prescritos
                     SET status_receita = 'Suspensa',
                         data_hora_suspensao = :data_hora_realizada,
                         ultima_dose_tomada = :data_hora_realizada
                     WHERE id = :medicamento_id
                 ");
                 $stmtSuspende->execute([
                     ':data_hora_realizada' => $dataHoraRealizada,
                     ':medicamento_id' => $medicamentoId
                 ]);
                 error_log("Medicamento $medicamentoId suspenso.");

                 // *** OPCIONAL: Limpar doses futuras na agenda_medicamentos ***
                 // Dependendo da sua lógica de negócio, você pode querer apagar
                 // todas as doses futuras pendentes (status = NULL) aqui.
                 // Ex: DELETE FROM agenda_medicamentos WHERE medicamento_id = :mid AND status IS NULL AND data_hora_agendada > NOW()
             }
        }


        json(['success' => true, 'message' => 'Registro atualizado com observação.']);
        error_log("==== FIM atualizar-status-agenda-com-observacao: sucesso ====");
        exit;

    } catch (Exception $e) {
        error_log("EXCEÇÃO: " . $e->getMessage());
        json(['success' => false, 'error' => 'Erro: ' . $e->getMessage()]);
        exit;
    }
}

// *** NOVA AÇÃO PARA ATUALIZAR A PROBABILIDADE DE CURA ***
if ($action === 'update-survival-probability') {
    $patientId = $input['patientId'] ?? null;
    $probability = $input['probability'] ?? null;
    $taskProgress = $input['task_progress'] ?? null;
    $taskCompleted = $input['task_completed'] ?? null;

    /*
    if (!$pacienteId )  {
        // Log de erro
        error_log("ERRO (update-survival-probability): Parâmetros obrigatórios ausentes. ID: $patientId, Probabilidade: $probability, quantidade $taskCompleted e progresso de tarefas: $taskProgress");
        json(['success' => false, 'message' => 'patientId'. $patientId . ', probability '.$probability.', task_completed '.$taskCompleted.' e task_progress '. $taskProgress .' são requeridos.']);
        exit;
    } */

    // Garante que o valor seja um float e está dentro dos limites lógicos (1 a 100) $probability = max(1, min(100, (float)$rawProbability));
    $probabilityFloat = floatval($probability);
    $probabilityFloat = max(1, min(100.0, $probabilityFloat));

    try {
        // Query SQL para atualizar o campo survivalProbability
        $sql = "UPDATE patients SET survivalProbability = :probability, tasksCompleted = :tc, taskProgress = :tp, updated_at = NOW() WHERE id = :patientId";
        $stmt = $pdo->prepare($sql);

        if ($stmt->execute([':probability' => $probabilityFloat, ':tc' => $taskCompleted, ':tp' => $taskProgress, ':patientId' => $patientId])) {
            // Log de sucesso
            error_log("✅ Probabilidade de Cura salva: $probabilityFloat, o quantidade $$taskCompleted e progresso de tarefas $taskProgress para o Paciente ID: $patientId");
            json(['success' => true]);
        } else {
            // Log de erro de execução SQL
            error_log("❌ ERRO SQL (update-survival-probability): Falha ao executar a query.");
            json(['success' => false, 'message' => 'Falha ao atualizar no banco de dados.']);
        }
    } catch (PDOException $e) {
        // Log de exceção PDO
        error_log("❌ EXCEÇÃO PDO (update-survival-probability): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro de banco de dados: ' . $e->getMessage()]);
    }
    exit;
}

/* save-diary-entry */
if ($action === 'save-diary-entry') {
    $patientId = $input['patientId'] ?? null;
    $caregiverId = $input['caregiverId'] ?? null;
    $actionType = $input['action_type'] ?? null;
    $value1 = $input['value_1'] ?? null;
    $unit1 = $input['unit_1'] ?? null;
    $value2 = $input['value_2'] ?? null; // Opcional
    $unit2 = $input['unit_2'] ?? null;   // Opcional
    $notes = $input['notes'] ?? null;    // Opcional

    if (!$patientId || !$caregiverId || !$actionType || !$unit1 || ($value1 <= 0 && $value2 <= 0)) {
        error_log("ERRO (save-diary-entry): Campos obrigatórios ausentes.");
        json(['success' => false, 'message' => 'Campos obrigatórios (ID, Tipo de Ação, Valor e Unidade) são requeridos.']);
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO diary (
                paciente_id, caregiver_id, action_type, 
                value_1, unit_1, value_2, unit_2, notes,
                created_at 
            ) VALUES (
                :paciente_id, :caregiver_id, :action_type, 
                :value_1, :unit_1, :value_2, :unit_2, :notes,
                NOW()   
            )
        ");

        $stmt->execute([
            ':paciente_id' => $patientId,
            ':caregiver_id' => $caregiverId,
            ':action_type' => $actionType,
            ':value_1' => $value1,
            ':unit_1' => $unit1,
            ':value_2' => $value2,
            ':unit_2' => $unit2,
            ':notes' => $notes
        ]);

        json(['success' => true, 'message' => 'Registro salvo com sucesso.']);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (save-diary-entry): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar diário: ' . $e->getMessage()]);
    }
    exit;
}

// Adicione esta Action para processar o Chat/Conselhos via Backend
 if ($action === 'gemini-chat') {
    // 1. Garante que lemos o JSON enviado pelo Javascript
    $rawInput = file_get_contents('php://input');
    $inputData = json_decode($rawInput, true);
    
    // 2. Validação segura
    $prompt = $inputData['prompt'] ?? '';
    $systemPrompt = $inputData['systemPrompt'] ?? '';

    if (empty($prompt)) {
        json(['success' => false, 'message' => 'O prompt está vazio.']);
    }

    // 3. Verifica a chave (Sua chave deve estar no define GEMINI_API_KEY lá em cima)
    if (!defined('GEMINI_API_KEY') || empty(GEMINI_API_KEY)) {
        json(['success' => false, 'message' => 'Erro no servidor: Chave da API não configurada.']);
    }

    // 4. Configuração da API (Modelo 1.5 Flash é o mais seguro para migração)
    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" . GEMINI_API_KEY;

    // 5. Monta o corpo da requisição
    $finalText = $systemPrompt ? ("Instrução do Sistema: $systemPrompt\n\nUsuário: $prompt") : $prompt;
    
    $payload = [
        'contents' => [
            ['parts' => [['text' => $finalText]]]
        ]
    ];

    // 6. Executa o cURL com tratamento de erro SSL
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_SSL_VERIFYPEER => false, // Importante para evitar bloqueio em alguns servidores
        CURLOPT_TIMEOUT => 30
    ]);

    $response = curl_exec($ch);
    $curlError = curl_error($ch);
    curl_close($ch);

    // 7. Processa a resposta
    if ($curlError) {
        error_log("Erro cURL Gemini: $curlError"); // Salva no log do servidor
        json(['success' => false, 'message' => "Falha de conexão com o Google."]);
    }

    $decoded = json_decode($response, true);
    
    // Verifica se o Google retornou erro
    if (isset($decoded['error'])) {
        error_log("Erro API Gemini: " . json_encode($decoded['error']));
        json(['success' => false, 'message' => "Erro da IA: " . ($decoded['error']['message'] ?? 'Desconhecido')]);
    }

    $textoGerado = $decoded['candidates'][0]['content']['parts'][0]['text'] ?? '';

    if ($textoGerado) {
        json(['success' => true, 'data' => $textoGerado]);
    } else {
        json(['success' => false, 'message' => 'A IA não retornou texto.']);
    }
}

/**
 * Função para chamar a API Gemini Vision e extrair texto/dados de imagens
 * @param string $base64Image Imagem em formato base64 (sem prefixo data:image/...)
 * @param string $prompt Instrução para o Gemini sobre o que extrair
 * @return array Resposta da API ou erro
 */
 /*
function callGeminiVisionAPI($base64Image, $prompt) {
    $apiKey = GEMINI_API_KEY;
    $model = GEMINI_MODEL;
    $apiUrl = "https://generativelanguage.googleapis.com/v1beta/models/{$model}:generateContent?key={$apiKey}";
    
    // Montar o payload da requisição
    $payload = [
        'contents' => [
            [
                'parts' => [
                    [
                        'text' => $prompt
                    ],
                    [
                        'inline_data' => [
                            'mime_type' => 'image/jpeg',
                            'data' => $base64Image
                        ]
                    ]
                ]
            ]
        ],
        'generationConfig' => [
            'temperature' => 0.2, // Baixa temperatura para respostas mais precisas
            'maxOutputTokens' => 1000
        ]
    ];
    
    // Fazer requisição HTTP via cURL
    $ch = curl_init($apiUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_TIMEOUT, 30); // Timeout de 30 segundos
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    // Tratamento de erros de conexão
    if ($curlError) {
        error_log("❌ ERRO cURL (Gemini Vision): $curlError");
        return ['success' => false, 'error' => 'Erro de conexão com a API: ' . $curlError];
    }
    
    if ($httpCode !== 200) {
        error_log("❌ ERRO HTTP (Gemini Vision): HTTP $httpCode - Response: $response");
        return ['success' => false, 'error' => "Erro da API Gemini (HTTP $httpCode)"];
    }
    
    // Decodificar resposta JSON
    $result = json_decode($response, true);
    
    if (!$result || !isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        error_log("❌ ERRO (Gemini Vision): Resposta inválida ou vazia.");
        return ['success' => false, 'error' => 'Resposta inválida da API Gemini'];
    }
    
    // Extrair o texto da resposta
    $extractedText = $result['candidates'][0]['content']['parts'][0]['text'];
    error_log("✅ Gemini Vision: Texto extraído com sucesso.");
    
    return ['success' => true, 'text' => $extractedText];
}
   */
  
/**
 * Função para chamar a API Gemini Vision e extrair texto/dados de imagens
 * Implementa Retry com Exponential Backoff para lidar com HTTP 429.
 * @param string $base64Image Imagem em formato base64 (sem prefixo data:image/...)
 * @param string $prompt Instrução para o Gemini sobre o que extrair
 * @return array Resposta da API ou erro
 */
function callGeminiVisionAPI($base64Image, $prompt) {
    $apiKey = GEMINI_API_KEY;
    $model = GEMINI_MODEL;
    $apiUrl = "https://generativelanguage.googleapis.com/v1beta/models/{$model}:generateContent?key={$apiKey}";
    
    // --- Configurações de Retry ---
    $maxRetries = 5;
    $initialDelaySeconds = 2; // Começa com 2 segundos de atraso
    
    $response = null;
    $httpCode = 0;
    
    for ($retry = 0; $retry < $maxRetries; $retry++) {
        
        // Montar o payload da requisição (mesmo código original)
        $payload = [
            'contents' => [
                [
                    'parts' => [
                        [ 'text' => $prompt ],
                        [ 'inline_data' => [ 'mime_type' => 'image/jpeg', 'data' => $base64Image ] ]
                    ]
                ]
            ],
            'generationConfig' => [
                'temperature' => 0.2,
                'maxOutputTokens' => 1000
            ]
        ];
        
        // Fazer requisição HTTP via cURL
        $ch = curl_init($apiUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        // 1. Tratamento de Erro de Conexão cURL
        if ($curlError) {
            error_log("❌ ERRO cURL (Gemini Vision): $curlError");
            if ($retry === $maxRetries - 1) {
                return ['success' => false, 'error' => 'Erro fatal de conexão com a API após retentativas: ' . $curlError];
            }
        }
        
        // 2. Tratamento de Sucesso
        if ($httpCode === 200) {
            break; // Sai do loop e processa a resposta
        }
        
        // 3. Tratamento de Retry (429 ou 5xx)
        if ($httpCode === 429 || $httpCode >= 500) {
            if ($retry < $maxRetries - 1) {
                // Cálculo do Backoff Exponencial
                $delay = $initialDelaySeconds * pow(2, $retry);
                // Adiciona Jitter (pequena variação aleatória para evitar novas colisões)
                $delay += rand(0, 1000) / 1000; 
                
                error_log("❌ ERRO HTTP (Gemini Vision): HTTP $httpCode. Tentando novamente em " . number_format($delay, 2) . "s...");
                sleep( (int) ceil($delay) ); // Pausa o script
                continue; // Próximo retry
            }
            
            // Falha no último retry
            error_log("❌ ERRO HTTP (Gemini Vision): HTTP $httpCode. Falha após $maxRetries retentativas.");
            return ['success' => false, 'error' => "Erro fatal da API Gemini (HTTP $httpCode) após retentativas."];
        }
        
        // 4. Outros Erros HTTP (Não recuperáveis - ex: 400, 401, 403)
        error_log("❌ ERRO HTTP (Gemini Vision): HTTP $httpCode - Response: $response");
        return ['success' => false, 'error' => "Erro não recuperável da API Gemini (HTTP $httpCode)"];
    } // Fim do Loop de Retry
    
    // O restante da função (Decodificar resposta e extrair texto) permanece inalterado:
    
    // Decodificar resposta JSON
    $result = json_decode($response, true);
    
    if (!$result || !isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        error_log("❌ ERRO (Gemini Vision): Resposta inválida ou vazia.");
        return ['success' => false, 'error' => 'Resposta inválida da API Gemini'];
    }
    
    // Extrair o texto da resposta
    $extractedText = $result['candidates'][0]['content']['parts'][0]['text'];
    error_log("✅ Gemini Vision: Texto extraído com sucesso.");
    
    return ['success' => true, 'text' => $extractedText];
}   
   
/**
 * Função auxiliar para parsear resposta JSON do Gemini
 * @param string $text Texto retornado pela API (pode conter markdown)
 * @return array Dados estruturados ou array vazio
 */
function parseGeminiResponse($text) {
    // Remove markdown code blocks se existirem
    $text = preg_replace('/```json\s*|\s*```/', '', $text);
    $text = trim($text);
    
    // Tenta decodificar como JSON
    $decoded = json_decode($text, true);
    
    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
        return $decoded;
    }
    
    error_log("⚠️ Falha ao parsear JSON do Gemini. Texto bruto: " . substr($text, 0, 200));
    return [];
}

// Endpoint de Análise de OCR com Gemini Vision
// Endpoint de Análise de OCR com Gemini Vision (IMPLEMENTAÇÃO REAL)
if ($action === 'ocr-analyze-document') {
    $base64Image = $input['image'] ?? null;
    $documentType = $input['type'] ?? null;
    
    if (!$base64Image || !$documentType) {
        json(['success' => false, 'message' => 'Imagem e tipo de documento são obrigatórios para OCR.']);
    }

    // ========== PROMPTS ESPECÍFICOS PARA CADA TIPO DE DOCUMENTO ==========
    $prompts = [
        'recipe' => 'Analise esta receita médica e extraia APENAS os seguintes dados em formato JSON válido:
{
  "nome_medicamento": "nome do medicamento",
  "dosagem": número da dosagem (apenas número),
  "unidade_dosagem": "unidade (mg, ml, etc)",
  "intervalo_horas": número de horas entre doses (apenas número),
  "data_hora_inicio": "YYYY-MM-DDTHH:MM:SS" (formato ISO ou deixe vazio),
  "medico_prescritor": "nome do médico"
}

IMPORTANTE:
- Retorne APENAS o JSON, sem texto adicional
- Se algum campo não estiver visível, use null
- Para data_hora_inicio, se não houver data explícita, use null',

        'blood' => 'Analise este exame laboratorial e extraia os dados em formato JSON válido:
{
  "campo_chave": "nome do exame/parâmetro",
  "valor_lido": número ou texto do resultado,
  "unidade_medida": "unidade de medida (g/dL, mg/dL, etc)",
  "observacoes": "observações relevantes (se houver)"
}

IMPORTANTE:
- Retorne APENAS o JSON, sem texto adicional
- Foque no primeiro/principal resultado visível
- Se houver múltiplos exames, escolha o mais proeminente',

        'monitor' => 'Analise este monitor de UTI e extraia TODOS os sinais vitais visíveis em formato JSON:
{
  "FrequĂȘncia CardĂ­aca": número (ou null),
  "Unidade_FC": "bpm",
  "FrequĂȘncia RespiratĂłria": nĂșmero (ou null),
  "Unidade_FR": "rpm",
  "Oximetria (SpO2)": nĂșmero (ou null),
  "Unidade_SpO2": "%",
  "PA_SistĂłlica": nĂșmero (ou null),
  "PA_DiastĂłlica": nĂșmero (ou null),
  "Unidade_PA": "mmHg",
  "Temperatura": nĂșmero decimal (ou null),
  "Unidade_Temp": "ÂșC",
  "observacoes": "qualquer alerta ou observação visível"
}

IMPORTANTE:
- Retorne APENAS o JSON, sem texto adicional
- Use null para campos nĂ£o visĂ­veis na imagem
- Seja preciso nos valores numĂ©ricos'
    ];

    // Verifica se o tipo de documento Ă© vĂĄlido
    if (!isset($prompts[$documentType])) {
        json(['success' => false, 'message' => 'Tipo de documento não suportado para OCR.']);
    }

    $prompt = $prompts[$documentType];
    error_log("🔍 Iniciando OCR para tipo: $documentType");

    // ========== CHAMADA REAL À API GEMINI VISION ==========
    $geminiResponse = callGeminiVisionAPI($base64Image, $prompt);

    if (!$geminiResponse['success']) {
        error_log("❌ Erro na chamada Gemini Vision: " . $geminiResponse['error']);
        json(['success' => false, 'message' => $geminiResponse['error']]);
    }

    // ========== PROCESSAR RESPOSTA DO GEMINI ==========
    $extractedText = $geminiResponse['text'];
    $parsedData = parseGeminiResponse($extractedText);

    if (empty($parsedData)) {
        error_log("⚠️ Gemini retornou texto não estruturado. Tentando fallback manual...");
        
        // Fallback: tentar extrair JSON manualmente se o Gemini retornou texto com JSON dentro
        if (preg_match('/\{[\s\S]*\}/', $extractedText, $matches)) {
            $parsedData = json_decode($matches[0], true);
        }
        
        if (empty($parsedData)) {
            json([
                'success' => false, 
                'message' => 'Não foi possível extrair dados estruturados da imagem.',
                'raw_text' => $extractedText
            ]);
        }
    }

    // ========== PÓS-PROCESSAMENTO ESPECÍFICO POR TIPO ==========
    if ($documentType === 'recipe') {
        // Garantir que data_hora_inicio esteja no formato correto para datetime-local
        if (!empty($parsedData['data_hora_inicio']) && $parsedData['data_hora_inicio'] !== null) {
            $parsedData['data_hora_inicio'] = date('Y-m-d\TH:i:s', strtotime($parsedData['data_hora_inicio']));
        } else {
            // Se não tiver data, usar 30 minutos a partir de agora
            $parsedData['data_hora_inicio'] = date('Y-m-d\TH:i:s', strtotime('+30 minutes'));
        }
        
        $parsedData['type'] = 'Medication';
        
    } elseif ($documentType === 'blood') {
        $parsedData['type'] = 'Exam';
        
    } elseif ($documentType === 'monitor') {
        $parsedData['type'] = 'VitalSign';
    }

    error_log("✅ OCR concluído com sucesso para tipo: $documentType");
    json(['success' => true, 'data' => $parsedData]);
    exit;
}

/*
// Endpoint para salvar dados de sinais vitais ou exames na tabela sinais_vitais_exames
if ($action === 'save-sinais-vitais-exames') {
    $pacienteId = $input['patientId'] ?? null;
    $caregiverId = $input['caregiverId'] ?? null;
    $tipoRegistro = $input['tipo_registro'] ?? 'Manual';
    
    // Dados obrigatórios para o registro
    $campoChave = $input['campo_chave'] ?? null;
    $valorLido = $input['valor_lido'] ?? null;
    $unidadeMedida = $input['unidade_medida'] ?? null;
    $observacoes = $input['observacoes'] ?? null;
    
    if (!$pacienteId || !$caregiverId || !$campoChave || $valorLido === null || !$unidadeMedida) {
        error_log("ERRO (save-sinais-vitais-exames): Campos obrigatórios ausentes.");
        json(['success' => false, 'message' => 'Dados obrigatórios (ID do paciente/cuidador, Campo Chave, Valor e Unidade) são requeridos.']);
        exit;
    }
    
    try {
        $stmt = $pdo->prepare("
            INSERT INTO sinais_vitais_exames (
                paciente_id, caregiver_id, tipo_registro, data_registro, 
                campo_chave, valor_lido, unidade_medida, observacoes
            ) VALUES (
                :paciente_id, :caregiver_id, :tipo_registro, NOW(), 
                :campo_chave, :valor_lido, :unidade_medida, :observacoes
            )
        ");

        $stmt->execute([
            ':paciente_id' => $pacienteId,
            ':caregiver_id' => $caregiverId,
            ':tipo_registro' => $tipoRegistro,
            ':campo_chave' => $campoChave,
            ':valor_lido' => $valorLido,
            ':unidade_medida' => $unidadeMedida,
            ':observacoes' => $observacoes
        ]);
        
        error_log("✅ Registro de $tipoRegistro salvo com sucesso. Chave: $campoChave, Valor: $valorLido $unidadeMedida.");
        json(['success' => true, 'message' => 'Registro de Exames/Sinais Vitais salvo.']);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (save-sinais-vitais-exames): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar no banco de dados: ' . $e->getMessage()]);
    }
    exit;
}
*/

if ($action === "save-sinais-vitais-exames") {
    // 1. Correção: Usar $input (JSON) em vez de $_POST
    // 2. Correção: Aceitar 'patientId' (do JS) ou 'paciente_id' (legado)
    $paciente_id = $input["patientId"] ?? $input["paciente_id"] ?? null;
    $caregiver_id = $input["caregiverId"] ?? $input["caregiver_id"] ?? null;
    
    $tipo_registro = $input["tipo_registro"] ?? 'Manual';
    $campo_chave = $input["campo_chave"] ?? null;
    $valor_lido = $input["valor_lido"] ?? null;
    $unidade_medida = $input["unidade_medida"] ?? null;
    
    $limite_inferior = $input["limite_inferior"] ?? null;
    $limite_superior = $input["limite_superior"] ?? null;
    $observacoes = $input["observacoes"] ?? null;

    // Validação
    if (!$paciente_id || !$campo_chave || $valor_lido === null || !$caregiver_id) { // Adicionada validação do cuidador
        json(['success' => false, 'message' => 'Dados incompletos: paciente, cuidador, chave e valor são obrigatórios.']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO sinais_vitais_exames
            (paciente_id, caregiver_id, tipo_registro, campo_chave, valor_lido, unidade_medida,
             limite_inferior, limite_superior, observacoes, data_registro)
            VALUES (:pid, :cid, :tipo, :chave, :valor, :unid, :min, :max, :obs, NOW())
        ");

        $stmt->execute([
            ':pid' => $paciente_id,
            ':cid' => $caregiver_id, // Parâmetro adicionado
            ':tipo' => $tipo_registro,
            ':chave' => $campo_chave,
            ':valor' => $valor_lido,
            ':unid' => $unidade_medida,
            ':min' => $limite_inferior,
            ':max' => $limite_superior,
            ':obs' => $observacoes
        ]);

        json(['success' => true, 'message' => 'Registro salvo com sucesso.']);

    } catch (PDOException $e) {
        error_log("❌ Erro ao salvar exame/sinal: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro no banco de dados: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para salvar a localização do cuidador
if ($action === 'update-caregiver-location') {
    $caregiverId = $input['caregiverId'] ?? null;
    $location = $input['location'] ?? null; // Espera "lat,lon"
    
    if (!$caregiverId || !$location) {
        json(['success' => false, 'message' => 'caregiverId e location são requeridos.']);
        exit;
    }
    
    try {
        // A tabela patient_caregivers é um pivot, a atualização deve ser feita por caregiver_id
        $stmt = $pdo->prepare("
            UPDATE patient_caregivers
            SET location = :location
            WHERE caregiver_id = :caregiver_id
        ");

        $stmt->execute([
            ':location' => $location,
            ':caregiver_id' => $caregiverId
        ]);
        
        // Retorna sucesso mesmo que 0 linhas tenham sido afetadas (pode não haver paciente associado ainda)
        error_log("✅ Localização do Cuidador ID $caregiverId atualizada para $location.");
        json(['success' => true]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (update-caregiver-location): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar localização: ' . $e->getMessage()]);
    }
    exit;
}

/* get-caregiver-chat-geo (messages from caregivers within 1km radius) */  
if ($action === 'get-caregiver-chat-geo') {
    $caregiverId = $_GET['caregiverId'] ?? null;
    $currentLocation = $_GET['currentLocation'] ?? null; // Espera "GPS: Lat X.XXX, Lon Y.YYY"
    
    if (!$caregiverId || !$currentLocation) {
        json(['success'=>false,'message'=>'caregiverId e currentLocation são requeridos.']);
        exit;
    }

    // 1. Parsing Seguro da Localização do cuidador (para definir o bounding box)
    $matches = [];
    if (!preg_match('/Lat\s*(-?\d+\.\d+),\s*Lon\s*(-?\d+\.\d+)/i', $currentLocation, $matches)) {
        json([
            'success' => false, 
            'message' => 'Formato de localização GPS inválido.'
        ]);
        exit;
    }
    
    $currentLat = (float) $matches[1]; // Latitude limpa
    $currentLon = (float) $matches[2]; // Longitude limpa
    
    // 2. Definir valores do Bounding Box (Aproximação)
    $radiusKm = 1.0; 
    $latDiff = $radiusKm / 111.04;
    $lonDiff = $radiusKm / (111.04 * cos(deg2rad($currentLat)));
    
    $minLat = $currentLat - $latDiff;
    $maxLat = $currentLat + $latDiff;
    $minLon = $currentLon - $lonDiff;
    $maxLon = $currentLon + $lonDiff;
    
    // 3. QUERY CORRIGIDA: Filtra por ccm.originLocation
    $sql = "
        SELECT 
            ccm.id, ccm.patient_id, ccm.sender_id, ccm.sender_nickname, ccm.text, ccm.created_at, ccm.chat_channel, 
            p.nickname AS patientnickname 
        FROM 
            caregiver_chat_messages ccm
        LEFT JOIN 
            patients p ON ccm.patient_id = p.id
        WHERE 
            ccm.chat_channel = 'geo_group'
            AND ccm.originLocation IS NOT NULL
            AND (
                -- CONDIÇÃO A: Garante que o próprio cuidador veja suas mensagens
                ccm.sender_id = :caregiverId 
                
                -- OU
                
                -- CONDIÇÃO B: A mensagem está no bounding box (USANDO ccm.originLocation)
                OR (
                    -- PARSING DA LATITUDE:
                    CAST(
                        TRIM(
                            SUBSTRING_INDEX(
                                SUBSTRING_INDEX(ccm.originLocation, ',', 1), 
                                'Lat ', -1
                            )
                        ) AS DECIMAL(10, 6)
                    )
                    BETWEEN :min_lat AND :max_lat
                    
                    -- E
                    AND 
                    
                    -- PARSING DA LONGITUDE:
                    CAST(
                        TRIM(
                            SUBSTRING_INDEX(
                                SUBSTRING_INDEX(ccm.originLocation, ',', -1), 
                                'Lon ', -1
                            )
                        ) AS DECIMAL(10, 6)
                    )
                    BETWEEN :min_lon AND :max_lon
                )
            )
        ORDER BY 
            ccm.created_at DESC
        LIMIT 50
    ";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':caregiverId', $caregiverId, PDO::PARAM_INT);
        $stmt->bindParam(':min_lat', $minLat);
        $stmt->bindParam(':max_lat', $maxLat);
        $stmt->bindParam(':min_lon', $minLon);
        $stmt->bindParam(':max_lon', $maxLon);
        
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        json(['success'=>true,'data'=>$rows]);

    } catch (PDOException $e) {
        error_log("❌ Erro SQL em get-caregiver-chat-geo: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao consultar o chat geográfico (SQL): ' . $e->getMessage()]);
    }
    exit; 
}

// api.php - NOVO: Endpoint para salvar dados de Medidas Físicas
if ($action === 'save-physical-measurements') {
    $pacienteId = $input['patientId'] ?? null;
    $caregiverId = $input['caregiverId'] ?? null;
    $peso = $input['weight'] ?? null;
    $altura = $input['height'] ?? null;
    $circAbdominal = $input['abdominalCircumference'] ?? null;
    $observacoes = $input['notes'] ?? null;

    if (!$pacienteId || !$caregiverId) {
        json(['success' => false, 'message' => 'IDs de paciente e cuidador são obrigatórios.']);
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO porte_fisico (
                paciente_id, caregiver_id, peso, altura, circunferencia_abdominal, observacoes
            ) VALUES (
                :pid, :cid, :peso, :altura, :circunferencia_abdominal, :observacoes
            )
        ");

        $stmt->execute([
            ':pid' => $pacienteId,
            ':cid' => $caregiverId,
            // Converte para float apenas se o valor não for nulo/vazio
            ':peso' => is_numeric($peso) ? floatval($peso) : null,
            ':altura' => is_numeric($altura) ? floatval($altura) : null,
            ':circunferencia_abdominal' => is_numeric($circAbdominal) ? floatval($circAbdominal) : null,
            ':observacoes' => $observacoes
        ]);

        json(['success' => true, 'message' => 'Medidas físicas salvas com sucesso.']);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (save-physical-measurements): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar porte físico: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - NOVO: Endpoint para obter o status de notificação
if ($action === 'get-notification-status') {
    $patientId = $_GET['patientId'] ?? null;
    if (!$patientId) json(['success' => false, 'message' => 'patientId requerido.']);

    $stmt = $pdo->prepare("SELECT Notification FROM patients WHERE id = :pid LIMIT 1");
    $stmt->execute([':pid' => $patientId]);
    $result = fetchRow($stmt);

    if ($result === null) json(['success' => false, 'message' => 'Paciente não encontrado.']);

    // Retorna 1 se Notification for 1, senão 0
    json(['success' => true, 'status' => (int)($result['Notification'] ?? 0)]);
}

// api.php - NOVO: Endpoint para atualizar o status de notificação (0 ou 1)
if ($action === 'update-notification-status') {
    $patientId = $input['patientId'] ?? null;
    $status = $input['status'] ?? null; // 0 para off, 1 para on

    if (!$patientId || $status === null) {
        json(['success' => false, 'message' => 'patientId e status requeridos.']);
    }

    $statusInt = (int)$status;

    try {
        $stmt = $pdo->prepare("UPDATE patients SET Notification = :status WHERE id = :pid");
        $stmt->execute([
            ':status' => $statusInt,
            ':pid' => $patientId
        ]);
        
        error_log("🔔 Status de Notificação do Paciente ID $patientId atualizado para $statusInt.");
        json(['success' => true]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (update-notification-status): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao atualizar status de notificação.']);
    }
    exit;
}



/* Atualizar perfil do Paciente (Doença, Alergias, etc.) */
if ($action === 'update-patient-profile') {
    $patientId = $input['patientId'] ?? null;
    $illness = trim($input['illness'] ?? '');
    $allergies = trim($input['allergies'] ?? '');

    if (!$patientId || !$illness) {
        json(['success'=>false,'message'=>'patientId e illness são requeridos.']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("
            UPDATE patients 
            SET illness = :illness, 
                allergies = :allergies
            WHERE id = :id
        ");

        $stmt->execute([
            ':illness' => $illness,
            ':allergies' => $allergies,
            ':id' => $patientId
        ]);

        json(['success' => true, 'message' => 'Perfil do paciente atualizado.']);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (update-patient-profile): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao atualizar perfil do paciente: ' . $e->getMessage()]);
    }
    exit;
}

/* Upload de Avatar para Cuidador ou Paciente */
if ($action === 'upload-avatar') {
    $userId = $input['userId'] ?? null;
    $targetType = $input['targetType'] ?? null; // 'caregiver' ou 'patient'
    $patientId = $input['patientId'] ?? null;
    $base64Image = $input['image'] ?? null;

    // 1. Validação
    if (!$userId || !$targetType || !$base64Image) {
        json(['success' => false, 'message' => 'Parâmetros incompletos.']);
        exit;
    }
    if ($targetType === 'patient' && !$patientId) {
        json(['success' => false, 'message' => 'patientId é requerido para avatar de paciente.']);
        exit;
    }

    // 2. Decodificar e Salvar Imagem
    $imageData = base64_decode($base64Image);
    $fileName = uniqid($targetType . '_') . '.jpg';
    $uploadDir = __DIR__ . '/uploads/'; // Certifique-se que a pasta 'uploads/' existe e tem permissão de escrita

    if (!is_dir($uploadDir)) {
        if (!mkdir($uploadDir, 0777, true)) {
            json(['success' => false, 'message' => 'Falha ao criar diretório de upload.']);
            exit;
        }
    }

    $filePath = $uploadDir . $fileName;
    if (file_put_contents($filePath, $imageData) === false) {
        json(['success' => false, 'message' => 'Falha ao salvar o arquivo no servidor.']);
        exit;
    }

    $avatarUrl = 'uploads/' . $fileName; // Caminho relativo que o front-end pode usar

    // 3. Atualizar o Banco de Dados
    try {
        if ($targetType === 'caregiver') {
            $stmt = $pdo->prepare("UPDATE users SET avatarUrl = :url WHERE id = :id");
            $stmt->execute([':url' => $avatarUrl, ':id' => $userId]);
            error_log("✅ Avatar do Cuidador $userId atualizado: $avatarUrl");
        } else {
            $stmt = $pdo->prepare("UPDATE patients SET avatarUrl = :url WHERE id = :id");
            $stmt->execute([':url' => $avatarUrl, ':id' => $patientId]);
            error_log("✅ Avatar do Paciente $patientId atualizado: $avatarUrl");
        }

        json(['success' => true, 'data' => ['avatarUrl' => $avatarUrl]]);

    } catch (PDOException $e) {
        // Em caso de falha no DB, tentar remover o arquivo
        @unlink($filePath);
        error_log("❌ EXCEÇÃO PDO (upload-avatar): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao atualizar DB: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Endpoint: save-appointment
if ($action === 'save-appointment') {
    // Campos obrigatórios de acordo com a estrutura da tabela
    $requiredFields = ['paciente_id', 'data_consulta', 'hora_consulta', 'tipo', 'descricao', 'local', 'profissional_contato','status_pagador'];
    
    foreach ($requiredFields as $field) {
        if (empty($input[$field])) {
            json(['success' => false, 'message' => "Campo obrigatório ausente: $field"]);
            exit;
        }
    }
    
    try {
        $stmt = $pdo->prepare("
           INSERT INTO AGENDA_EXAM_CON_PROC (
            paciente_id, 
            data_consulta, 
            hora_consulta, 
            tipo, 
            descricao, 
            jejum, 
            local, 
            profissional_contato, 
            telefone_clinica, 
            instrucoes_preparo, 
            status, 
            status_pagador
        )
        SELECT 
            :pid, 
            :data_con, 
            :hora_con, 
            :tipo, 
            :desc, 
            :jejum, 
            :local, 
            :prof_contato, 
            :tel_clinica, 
            :instrucoes, 
            :status_inicial,
            :status_Pagador
        FROM DUAL
        WHERE NOT EXISTS (
            SELECT 1 FROM AGENDA_EXAM_CON_PROC 
            WHERE paciente_id = :pid
              AND data_consulta = :data_con
              AND hora_consulta = :hora_con
              AND tipo = :tipo
              AND descricao = :desc
              AND local = :local
              AND profissional_contato = :prof_contato
              AND telefone_clinica = :tel_clinica
        )
        ");

        // O status inicial é 'Em aprovação', conforme definido na sua DDL
        $statusInicial = $input['status'] ?? 'Em aprovação';

        $stmt->execute([
            ':pid' => $input['paciente_id'],
            ':data_con' => $input['data_consulta'],
            ':hora_con' => $input['hora_consulta'],
            ':tipo' => $input['tipo'],
            ':desc' => $input['descricao'],
            ':jejum' => (int)($input['jejum'] ?? 0), // Garante que é INT
            ':local' => $input['local'],
            ':prof_contato' => $input['profissional_contato'],
            ':tel_clinica' => $input['telefone_clinica'] ?? null,
            ':instrucoes' => $input['instrucoes_preparo'] ?? null,
            ':status_inicial' => $statusInicial,
            ':status_Pagador' => $input['status_pagador']
        ]);

        $id = $pdo->lastInsertId();
        error_log("✅ Agendamento ID $id criado com sucesso para o paciente {$input['paciente_id']}.");
        
        json(['success' => true, 'data' => ['agendamento_id' => $id]]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (save-appointment): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar agendamento: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Endpoint: get-appointments
if ($action === 'get-appointments') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    
    try {
        // Busca agendamentos a partir da data atual (CURDATE()) até 90 dias no futuro.
        // O `DATE_ADD(CURDATE(), INTERVAL 90 DAY)` garante a janela.
        $sql = "
            SELECT 
                agendamento_id,
                DATE_FORMAT(data_consulta, '%Y-%m-%d') as data_consulta,
                hora_consulta,
                tipo,
                descricao,
                local,
                profissional_contato,
                telefone_clinica,
                instrucoes_preparo,
                status,
                jejum
            FROM 
                AGENDA_EXAM_CON_PROC
            WHERE 
                paciente_id = :pid
                AND data_consulta BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 90 DAY)
            ORDER BY 
                data_consulta ASC, 
                hora_consulta ASC
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':pid' => $pacienteId]);
        
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        error_log("✅ Buscados " . count($appointments) . " agendamentos para a linha do tempo do paciente $pacienteId.");
        
        json(['success' => true, 'data' => $appointments]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-appointments): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar agendamentos: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Endpoint: update-appointment-status
if ($action === 'update-appointment-status') {
    $agendamentoId = $input['agendamento_id'] ?? null;
    $novoStatus = $input['status'] ?? null;
    
    // Lista de status válidos para o ENUM da tabela
    $validStatuses = ['Em aprovação', 'Agendado', 'Realizado com Sucesso', 'Não Realizado', 'Cancelado', 'Recusado'];

    if (!$agendamentoId || !$novoStatus || !in_array($novoStatus, $validStatuses)) {
        json(['success' => false, 'message' => 'ID do agendamento ou status inválido/ausente.']);
        exit;
    }
    
    try {
        $stmt = $pdo->prepare("
            UPDATE AGENDA_EXAM_CON_PROC
            SET status = :status,
                data_atualizacao = NOW()
            WHERE agendamento_id = :id
        ");

        $stmt->execute([
            ':status' => $novoStatus,
            ':id' => $agendamentoId
        ]);
        
        // Verifica se a atualização foi bem-sucedida
        if ($stmt->rowCount() > 0) {
            error_log("✅ Status do Agendamento ID $agendamentoId atualizado para $novoStatus.");
            json(['success' => true, 'message' => 'Status atualizado com sucesso.']);
        } else {
            json(['success' => false, 'message' => 'Nenhum agendamento encontrado com este ID.']);
        }

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (update-appointment-status): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao atualizar status: ' . $e->getMessage()]);
    }
    exit;
}

/* Ação: Reagendar Compromisso 
   Recebe: agendamento_id, new_datetime (formato YYYY-MM-DDTHH:MM)
*/
if ($action === 'reschedule-appointment') {
    $agendamentoId = $input['agendamento_id'] ?? null;
    $newDateTime = $input['new_datetime'] ?? null;

    if (!$agendamentoId || !$newDateTime) {
        json(['success' => false, 'message' => 'ID do agendamento e nova data são obrigatórios.']);
    }

    try {
        // Separa data e hora do formato datetime-local (ex: 2023-10-25T14:30)
        $timestamp = strtotime($newDateTime);
        $novaData = date('Y-m-d', $timestamp);
        $novaHora = date('H:i:s', $timestamp);

        // Atualiza a data, a hora e reseta o status para 'Em aprovação'
        // Nota: Ajuste o nome da tabela (AGENDA_EXAM_CON_PROC) se for diferente no seu banco real
        $stmt = $pdo->prepare("
            UPDATE AGENDA_EXAM_CON_PROC 
            SET data_consulta = :novaData, 
                hora_consulta = :novaHora, 
                status = 'Em aprovação',
                data_atualizacao = NOW()
            WHERE agendamento_id = :id
        ");

        $stmt->execute([
            ':novaData' => $novaData,
            ':novaHora' => $novaHora,
            ':id' => $agendamentoId
        ]);

        if ($stmt->rowCount() > 0) {
            json(['success' => true, 'message' => 'Reagendamento realizado com sucesso.']);
        } else {
            // Se rowCount for 0, pode ser que o ID não exista ou a data seja a mesma
            json(['success' => true, 'message' => 'Dados atualizados (ou idênticos).']);
        }

    } catch (PDOException $e) {
        error_log("Erro ao reagendar: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro no banco de dados ao reagendar.']);
    }
}

// api.php - NOVO Endpoint: get-all-appointments
if ($action === 'get-all-appointments') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    
    try {
        // Busca TODOS os agendamentos do paciente (passado e futuro)
        $sql = "
            SELECT 
                agendamento_id,
                DATE_FORMAT(data_consulta, '%Y-%m-%d') as data_consulta,
                hora_consulta,
                tipo,
                descricao,
                local,
                profissional_contato,
                telefone_clinica,
                instrucoes_preparo,
                status,
                jejum
            FROM 
                AGENDA_EXAM_CON_PROC
            WHERE 
                paciente_id = :pid
            ORDER BY 
                data_consulta DESC, -- Ordena do mais recente para o mais antigo (para exibição em lista)
                hora_consulta DESC
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':pid' => $pacienteId]);
        
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        json(['success' => true, 'data' => $appointments]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-all-appointments): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar todos agendamentos: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Bem estar do cuidador
// api.php - NOVO: Salvar bem-estar do cuidador
if ($action === 'save-caregiver-wellness') {
    $caregiverId = $input['caregiverId'] ?? null;
    $actionType = $input['action'] ?? null; // 'meal', 'sleep' ou 'breathing'
    $timestamp = $input['timestamp'] ?? date('Y-m-d H:i:s');
    
    if (!$caregiverId || !$actionType) {
        json(['success' => false, 'message' => 'caregiverId e action são obrigatórios.']);
        exit;
    }
    
    try {
        // 1. Criar tabela se não existir (Adicionado 'breathing' na definição)
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS caregiver_wellness (
                id INT AUTO_INCREMENT PRIMARY KEY,
                caregiver_id INT NOT NULL,
                action_type ENUM('meal', 'sleep', 'breathing') NOT NULL,
                recorded_at DATETIME NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (caregiver_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ");

        // 2. ATUALIZAÇÃO AUTOMÁTICA (Importante!)
        // Se a tabela já existia antes apenas com 'meal' e 'sleep', este comando
        // atualiza a coluna para aceitar 'breathing' também.
        // O comando IGNORE ou a supressão de erro é implícita se não mudar nada, 
        // mas para garantir, rodamos o MODIFY.
        $pdo->exec("
            ALTER TABLE caregiver_wellness 
            MODIFY COLUMN action_type ENUM('meal', 'sleep', 'breathing') NOT NULL
        ");
        
        // 3. Inserir registro
        $stmt = $pdo->prepare("
            INSERT INTO caregiver_wellness (caregiver_id, action_type, recorded_at, created_at)
            VALUES (:cid, :action, NOW(), NOW())
        ");
        
        $stmt->execute([
            ':cid' => $caregiverId,
            ':action' => $actionType
            //':timestamp' => $timestamp
        ]);
        
        json(['success' => true, 'message' => 'Bem-estar registrado com sucesso.']);
        
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (save-caregiver-wellness): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao salvar: ' . $e->getMessage()]);
    }
    exit;
}

if ($action === 'get-caregiver-wellness') {
    // Obtém o ID via GET
    $caregiverId = $_GET['caregiverId'] ?? null;

    if (!$caregiverId) {
        json(['success' => false, 'message' => 'caregiverId é obrigatório.']);
        exit;
    }

    try {
        // Consulta Agregada:
        // 1. Filtra pelo ID do cuidador.
        // 2. Filtra pela DATA de hoje (DATE(recorded_at) = CURDATE()).
        // 3. Soma as refeições e respirações.
        // 4. Verifica se existe registro de sono (MAX retorna 1 se existir, 0 se não).
        $sql = "
            SELECT 
                COALESCE(SUM(CASE WHEN action_type = 'meal' THEN 1 ELSE 0 END), 0) as meals_count,
                COALESCE(MAX(CASE WHEN action_type = 'sleep' THEN 1 ELSE 0 END), 0) as has_slept,
                COALESCE(SUM(CASE WHEN action_type = 'breathing' THEN 1 ELSE 0 END), 0) as breathing_count
            FROM caregiver_wellness
            WHERE caregiver_id = :cid 
              AND DATE(recorded_at) = CURDATE()
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':cid' => $caregiverId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        // Prepara os dados para o Frontend
        // Se a tabela estiver vazia ou sem registros hoje, o SQL acima já garante 0 graças ao COALESCE,
        // mas garantimos a estrutura aqui.
        $wellnessData = [
            'mealsToday' => (int)($result['meals_count'] ?? 0),
            'sleptToday' => (bool)($result['has_slept'] ?? 0),
            'breathingToday' => (int)($result['breathing_count'] ?? 0)
        ];

        json(['success' => true, 'data' => $wellnessData]);

    } catch (PDOException $e) {
        // Tratamento específico: Se a tabela ainda não existir (primeiro acesso antes de salvar qualquer coisa),
        // retornamos dados zerados em vez de erro, para a tela carregar normalmente.
        if (strpos($e->getMessage(), "doesn't exist") !== false) {
            json(['success' => true, 'data' => [
                'mealsToday' => 0, 
                'sleptToday' => false, 
                'breathingToday' => 0
            ]]);
        }
        
        error_log("❌ Erro get-caregiver-wellness: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - NOVO Endpoint: get-patient-data
if ($action === 'get-patient-data'){
    $pacienteId = $_GET['paciente_id'] ?? null;
    
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    
    try {
        // ✅ CORREÇÃO: Usar a tabela correta 'patients' e buscar dados do cuidador
        $sql = "
            SELECT 
                p.id as paciente_id,
                p.nickname as nome,
                p.birth_date as data_nascimento,
                p.gender as sexo,
                p.illness as condicao_medica_principal,
                p.allergies,
                p.weight,
                p.height,
                p.avatarUrl as foto_url,
                u.nickname as nome_cuidador_principal
            FROM 
                patients p
            LEFT JOIN 
                patient_caregivers pc ON p.id = pc.patient_id
            LEFT JOIN 
                users u ON pc.caregiver_id = u.id
            WHERE 
                p.id = :pid
            LIMIT 1
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([':pid' => $pacienteId]);
        
        $patientData = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($patientData) {
            // Calcula a idade com base na data de nascimento
            if ($patientData['data_nascimento']) {
                $dataNascimento = new DateTime($patientData['data_nascimento']);
                $hoje = new DateTime();
                $idade = $dataNascimento->diff($hoje)->y;
                $patientData['idade'] = $idade;
            } else {
                $patientData['idade'] = 'Não informada';
            }
            
            // Formata o sexo para exibição
            if ($patientData['sexo'] === 'male') {
                $patientData['sexo_formatado'] = 'Masculino';
            } elseif ($patientData['sexo'] === 'female') {
                $patientData['sexo_formatado'] = 'Feminino';
            } else {
                $patientData['sexo_formatado'] = 'Não informado';
            }
            
            json(['success' => true, 'data' => $patientData]);
        } else {
            json(['success' => false, 'message' => 'Paciente não encontrado.']);
        }

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-patient-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados do paciente: ' . $e->getMessage()]);
    }
    exit;  
}


// Endpoint para nutrição
if ($action === 'get-nutrition-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    
    // Define período padrão (últimas 24 horas se não especificado)
    if (empty($dataInicio) || empty($dataFim)) { // *** CORREÇÃO DE SINTAXE APLICADA AQUI ***
        $dataFim = date('Y-m-d H:i:s');
        $dataInicio = date('Y-m-d H:i:s', strtotime('-24 hours'));
    }
    
    try {
        // Consulta: Consumo de Líquidos (mL)
     $stmtLiquidos = $pdo->prepare("
            SELECT
                DATE(created_at) as data,
                HOUR(created_at) as hora,
                SUM(value_1) as total_ml
            FROM diary
            WHERE paciente_id = :pid
                AND action_type = 'meds'
                -- Aceita 'ml' (antigo) ou 'unitMl' (novo traduzido)
                AND unit_1 IN ('ml', 'unitMl') 
                AND created_at BETWEEN :data_inicio AND :data_fim
            GROUP BY DATE(created_at), HOUR(created_at)
            ORDER BY created_at ASC
        ");
        $stmtLiquidos->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        
        $liquidos = $stmtLiquidos->fetchAll(PDO::FETCH_ASSOC);
        
        // Consulta: Ingestão de Sólidos/Calorias (estimativa baseada em refeições)
        $stmtCalorias = $pdo->prepare("
            SELECT 
                DATE(created_at) as data,
                HOUR(created_at) as hora,
                SUM(value_1) as total_gramas,
                COUNT(*) as num_refeicoes
            FROM diary
            WHERE paciente_id = :pid
                AND action_type = 'food'
                -- Aceita 'g' (antigo) ou 'unitG' (novo traduzido)
                AND unit_1 IN ('g', 'unitG') 
                AND created_at BETWEEN :data_inicio AND :data_fim
            GROUP BY DATE(created_at), HOUR(created_at)
            ORDER BY created_at ASC
        ");
        
        $stmtCalorias->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        
        $calorias = $stmtCalorias->fetchAll(PDO::FETCH_ASSOC);
        
        // Calcular totais e médias
        $totalLiquidos = array_sum(array_column($liquidos, 'total_ml'));
        $totalRefeicoes = array_sum(array_column($calorias, 'num_refeicoes'));
        
        json([
            'success' => true,
            'data' => [
                'liquidos' => $liquidos,
                'ingestao_solida' => $calorias, // Chave renomeada para ser mais precisa
                'totais' => [
                    'liquidos_ml' => (float)$totalLiquidos,
                    'refeicoes' => (int)$totalRefeicoes,
                    'meta_liquidos' => 2000, // Meta diária padrão
                    'meta_calorias' => 1800 // Meta diária padrão
                ],
                'periodo' => [
                    'inicio' => $dataInicio,
                    'fim' => $dataFim
                ]
            ]
        ]);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-nutrition-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados nutricionais: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para buscar dados de medidas físicas históricas
// Endpoint para buscar dados de medidas físicas históricas
if ($action === 'get-physical-measurements') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    
    // Define período padrão (últimos 6 meses)
    /*
    if (empty($dataInicio) || empty($dataFim)) {
        $dataFim = date('Y-m-d H:i:s');
        $sixMonthsAgo = new DateTime();
        $sixMonthsAgo->modify('-6 months');
        $dataInicio = $sixMonthsAgo->format('Y-m-d H:i:s');
    } */
    
        // Define período padrão (últimas 24 horas se não especificado)
    if (empty($dataInicio) || empty($dataFim)) { // *** CORREÇÃO DE SINTAXE APLICADA AQUI ***
        $dataFim = date('Y-m-d H:i:s');
        $dataInicio = date('Y-m-d H:i:s', strtotime('-24 hours'));
    }

    try {
        $stmt = $pdo->prepare("
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as data_registro,        /* CORREÇÃO CRÍTICA AQUI */
                peso as weight,                                                        
                altura as height,                                                      
                circunferencia_abdominal as abdominal_circumference
            FROM porte_fisico
            WHERE paciente_id = :pid
            AND created_at BETWEEN :data_inicio AND :data_fim
            ORDER BY created_at ASC
        ");
        
        $stmt->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        
        $measurements = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        json([
            'success' => true,
            'data' => $measurements,
            'periodo' => [
                'inicio' => $dataInicio,
                'fim' => $dataFim
            ]
        ]);
        
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-physical-measurements): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de medidas físicas: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para medicamentos ativos
if ($action === 'get-pharmacy-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    // Define período padrão (últimos 30 dias)
    if (empty($dataInicio) || empty($dataFim)) { // *** CORREÇÃO DE SINTAXE APLICADA AQUI ***
        $dataFim = date('Y-m-d');
        $dataInicio = date('Y-m-d', strtotime('-30 days'));
    }
    
    try {
        // 1. Medicamentos Ativos
        $stmtAtivos = $pdo->prepare("
                SELECT
                    mp.nome_medicamento, 
                    mp.dosagem,          
                    mp.unidade_dosagem,  
                    mp.intervalo_horas, 
                    mp.data_hora_inicio, 
                    mp.status_pagador,
                    COUNT(ag.id) as doses_pendentes
                FROM medicamentos_prescritos mp
                LEFT JOIN agenda_medicamentos ag ON mp.id = ag.medicamento_id AND ag.status IS NULL
                WHERE mp.paciente_id = :pid
                    AND mp.status_receita = 'Ativa'
                GROUP BY mp.id
                ORDER BY mp.nome_medicamento
            ");
        $stmtAtivos->execute([':pid' => $pacienteId]);
        $medicamentosAtivos = $stmtAtivos->fetchAll(PDO::FETCH_ASSOC);
        
        // 2. Medicamentos Inativos (últimos 30 dias)
        $stmtInativos = $pdo->prepare("
            SELECT 
                nome_medicamento,
                status_receita,
                data_hora_suspensao,
                ultima_dose_tomada
            FROM medicamentos_prescritos
            WHERE paciente_id = :pid
                AND status_receita IN ('Suspensa', 'Concluída')
                AND (data_hora_suspensao BETWEEN :data_inicio AND :data_fim
                     OR ultima_dose_tomada BETWEEN :data_inicio AND :data_fim)
            ORDER BY COALESCE(data_hora_suspensao, ultima_dose_tomada) DESC
            LIMIT 10
        ");
        
        $stmtInativos->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        $medicamentosInativos = $stmtInativos->fetchAll(PDO::FETCH_ASSOC);
        
        // 3. Cálculo de Compliance (Adesão)
        $stmtCompliance = $pdo->prepare("
            SELECT 
                COUNT(*) as total_agendado,
                SUM(CASE WHEN status = 'realizada' THEN 1 ELSE 0 END) as total_realizado
            FROM agenda_medicamentos
            WHERE paciente_id = :pid
                AND data_hora_agendada BETWEEN :data_inicio AND :data_fim
                AND status IS NOT NULL
        ");
        
        $stmtCompliance->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        
        $compliance = $stmtCompliance->fetch(PDO::FETCH_ASSOC);
        $percentualCompliance = 0;
        
        if ($compliance && $compliance['total_agendado'] > 0) {
            $percentualCompliance = round(
                ($compliance['total_realizado'] / $compliance['total_agendado']) * 100,
                1
            );
        }
        
        // 4. Alertas Farmacêuticos (medicamentos com uso contínuo > 30 dias)
        $stmtAlertas = $pdo->prepare("
            SELECT 
                nome_medicamento,
                DATEDIFF(NOW(), data_hora_inicio) as dias_uso,
                'Uso contínuo prolongado' as tipo_alerta
            FROM medicamentos_prescritos
            WHERE paciente_id = :pid
                AND status_receita = 'Ativa'
                AND DATEDIFF(NOW(), data_hora_inicio) > 30
            ORDER BY dias_uso DESC
        ");
        
        $stmtAlertas->execute([':pid' => $pacienteId]);
        $alertas = $stmtAlertas->fetchAll(PDO::FETCH_ASSOC);
        
        json([
            'success' => true,
            'data' => [
                'medicamentos_ativos' => $medicamentosAtivos,
                'medicamentos_inativos' => $medicamentosInativos,
                'compliance' => [
                    'percentual' => $percentualCompliance,
                    'doses_realizadas' => (int)($compliance['total_realizado'] ?? 0),
                    'doses_agendadas' => (int)($compliance['total_agendado'] ?? 0)
                ],
                'alertas' => $alertas,
                'periodo' => [
                    'inicio' => $dataInicio,
                    'fim' => $dataFim
                ]
            ]
        ]);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-pharmacy-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados farmacêuticos: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para exames

// --------- START: Implementação melhorada get-exams-data -------------
/*
if ($action === 'get-exams-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;

    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }

    // Se não fornecer período, buscar últimos 90 dias por padrão
    if (!$dataInicio || !$dataFim) {
        $dataFim = date('Y-m-d') . ' 23:59:59';
        $dataInicio = date('Y-m-d', strtotime('-90 days')) . ' 00:00:00';
    } else {
        // normalizar formatos simples (aceita YYYY-MM-DD ou datetime)
        if (strlen($dataInicio) === 10) $dataInicio .= ' 00:00:00';
        if (strlen($dataFim) === 10)    $dataFim .= ' 23:59:59';
    }

    try {
        // Buscar todos os registros do paciente no período (ordenados)
        $sql = "
            SELECT 
                paciente_id,
                tipo_registro,
                data_registro,
                campo_chave,
                valor_lido,
                unidade_medida,
                limite_inferior,
                limite_superior,
                observacoes
            FROM sinais_vitais_exames
            WHERE paciente_id = :pid
              AND data_registro BETWEEN :data_inicio AND :data_fim
            ORDER BY campo_chave ASC, data_registro ASC
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Estruturar dados por parâmetro
        $sinaisVitaisKeys = [
            'Frequência Cardíaca','Frequencia Cardíaca','Frequência cardíaca','FC','Freq Cardíaca','Frequencia Cardiaca',
            'Frequência Respiratória','Frequencia Respiratoria','FR','Freq Respiratoria',
            'Oximetria','Saturação','SpO2','Oximetria (%)',
            'Temperatura','Temp','Temperatura (C)','Temperatura (°C)',
            'Pressão Arterial','PA','Pressao Arterial','Pressão'
        ];
        $dataByCampo = [];

        foreach ($rows as $r) {
            $campo = trim($r['campo_chave'] ?? '');
            if ($campo === '') continue;

            // Converter valor para float quando possível, mas manter original se texto
            $valor = $r['valor_lido'];
            if (is_numeric($valor)) {
                // permite vírgula decimal em registros brasileiros
                $valor = str_replace(',', '.', $valor);
                $valor = (float)$valor;
            }

            $entry = [
                'data_registro' => $r['data_registro'],
                'valor_lido' => $valor,
                'unidade_medida' => $r['unidade_medida'],
                'limite_inferior' => $r['limite_inferior'] !== null ? (float)$r['limite_inferior'] : null,
                'limite_superior' => $r['limite_superior'] !== null ? (float)$r['limite_superior'] : null,
                'observacoes' => $r['observacoes'] ?? null
            ];

            // Agrupar
            if (!isset($dataByCampo[$campo])) $dataByCampo[$campo] = [];
            $dataByCampo[$campo][] = $entry;
        }

        // Preparar resposta separando sinais vitais / exames laboratoriais
        $sinais_vitais = [];
        $exames_laboratoriais = [];

        foreach ($dataByCampo as $campo => $registros) {
            // ordenar por data_registro asc (já veio assim, mas garantimos)
            usort($registros, function($a,$b){ return strtotime($a['data_registro']) - strtotime($b['data_registro']); });

            // último registro
            $ultimo = end($registros);
            reset($registros);

            $item = [
                'campo' => $campo,
                'registros' => $registros,
                'ultimo_valor' => $ultimo['valor_lido'],
                'ultima_data' => $ultimo['data_registro'],
                'unidade_medida' => $ultimo['unidade_medida'],
                'limite_inferior' => $ultimo['limite_inferior'],
                'limite_superior' => $ultimo['limite_superior']
            ];

            // identificar pressão arterial separada (ex.: "Pressão Arterial" pode ter valor "120/80")
            if (stripos($campo, 'press') !== false) {
                // tentar separar sistólica/diastólica se valor estiver em formato "120/80"
                $extracted = [];
                foreach ($registros as $r) {
                    $v = $r['valor_lido'];
                    if (is_string($v) && strpos($v, '/') !== false) {
                        list($sist, $diast) = array_map('trim', explode('/', $v, 2));
                        $extracted[] = [
                            'data_registro' => $r['data_registro'],
                            'sistolica' => is_numeric($sist) ? (float)str_replace(',', '.', $sist) : $sist,
                            'diastolica' => is_numeric($diast) ? (float)str_replace(',', '.', $diast) : $diast,
                            'unidade_medida' => $r['unidade_medida'],
                            'limite_inferior' => $r['limite_inferior'],
                            'limite_superior' => $r['limite_superior']
                        ];
                    }
                }
                if (!empty($extracted)) {
                    $item['registros'] = $extracted;
                }
            }

            // classificar
            $isVital = false;
            foreach ($sinaisVitaisKeys as $k) {
                if (stripos($campo, $k) !== false) { $isVital = true; break; }
            }

            if ($isVital) $sinais_vitais[$campo] = $item;
            else $exames_laboratoriais[$campo] = $item;
        }

        // montar alertas simples (último valor fora do range)
        $alertas_criticos = [];
        foreach (array_merge($sinais_vitais, $exames_laboratoriais) as $campo => $it) {
            $ult = $it['ultimo_valor'];
            if ($ult !== null && is_numeric($ult) && ($it['limite_inferior'] !== null || $it['limite_superior'] !== null)) {
                $low = $it['limite_inferior'];
                $high = $it['limite_superior'];
                if (($low !== null && $ult < $low) || ($high !== null && $ult > $high)) {
                    $alertas_criticos[] = [
                        'campo' => $campo,
                        'valor' => $ult,
                        'unidade' => $it['unidade_medida'],
                        'ultima_data' => $it['ultima_data'],
                        'limite_inferior' => $low,
                        'limite_superior' => $high
                    ];
                }
            }
        }

        json([
            'success' => true,
            'data' => [
                'sinais_vitais' => $sinais_vitais,
                'exames_laboratoriais' => $exames_laboratoriais,
                'alertas_criticos' => $alertas_criticos,
                'periodo' => ['inicio' => $dataInicio, 'fim' => $dataFim]
            ]
        ]);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-exams-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de exames: ' . $e->getMessage()]);
    }
    exit;
}     
*/

// --------- START: Implementação melhorada get-exams-data -------------
if ($action === 'get-exams-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;

    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }

    // Buscar data de nascimento para calcular idade
    $stmtAge = $pdo->prepare("SELECT birth_date FROM patients WHERE id = ?");
    $stmtAge->execute([$pacienteId]);
    $birthRow = $stmtAge->fetch(PDO::FETCH_ASSOC);

    $idadeAnos = null;
    if ($birthRow && !empty($birthRow['birth_date'])) {
        $dob = new DateTime($birthRow['birth_date']);
        $now = new DateTime();
        $idadeAnos = $now->diff($dob)->y;
        $idadeMeses = $now->diff($dob)->m + ($idadeAnos * 12);
    }

    // Funções para calcular limites conforme idade
    function limitesFC($anos, $meses) {
        if ($meses <= 1) return [100,160];
        if ($meses <= 3) return [70,170];
        if ($meses <= 6) return [80,150];
        if ($meses <= 12) return [80,140];
        if ($anos <= 3) return [80,130];
        if ($anos <= 5) return [80,120];
        if ($anos <= 10) return [70,110];
        if ($anos <= 14) return [60,105];
        return [60,100];
    }

    function limitesFR($anos, $meses) {
        if ($meses <= 1) return [30,60];
        if ($meses <= 12) return [24,40];
        if ($anos <= 3) return [22,34];
        if ($anos <= 6) return [20,30];
        if ($anos <= 12) return [18,26];
        if ($anos <= 18) return [12,20];
        return [12,20];
    }

    function limitesPA_sistolica($anos) {
        if ($anos < 1) return [60,90];
        if ($anos <= 1) return [80,100];
        if ($anos <= 3) return [90,105];
        if ($anos <= 6) return [95,110];
        if ($anos <= 12) return [100,115];
        if ($anos <= 18) return [110,120];
        if ($anos <= 45) return [110,125];
        if ($anos <= 65) return [120,135];
        return [130,140];
    }

    function limitesPA_diastolica($anos) {
        if ($anos < 1) return [20,60];
        if ($anos <= 1) return [50,70];
        if ($anos <= 3) return [55,70];
        if ($anos <= 6) return [60,75];
        if ($anos <= 12) return [60,75];
        if ($anos <= 18) return [65,76];
        if ($anos <= 45) return [70,80];
        if ($anos <= 65) return [75,85];
        return [75,85];
    }

    function limitesSpO2($anos) {
        return [95,100]; // igual para quase todas idades
    }
    
    function limitesTemp($anos, $meses) {
        // Recém-nascidos (0–3 meses)
        if ($meses <= 3) return [36.5, 37.5];

        // Bebês e crianças (3 meses – 12 anos)
        if ($anos < 12) return [35.5, 37.5];

        // Adolescentes e adultos (12 – 65 anos)
        if ($anos < 65) return [36.1, 37.2];

        // Idosos (≥ 65 anos)
        return [35.8, 37.0];
    }

    // Se não fornecer período, buscar últimos 90 dias
    if (!$dataInicio || !$dataFim) {
        $dataFim = date('Y-m-d') . ' 23:59:59';
        $dataInicio = date('Y-m-d', strtotime('-90 days')) . ' 00:00:00';
    } else {
        if (strlen($dataInicio) === 10) $dataInicio .= ' 00:00:00';
        if (strlen($dataFim) === 10)    $dataFim .= ' 23:59:59';
    }

    try {
        $sql = "
            SELECT 
                paciente_id,
                tipo_registro,
                data_registro,
                campo_chave,
                valor_lido,
                unidade_medida,
                limite_inferior,
                limite_superior,
                observacoes
            FROM sinais_vitais_exames
            WHERE paciente_id = :pid
              AND data_registro BETWEEN :data_inicio AND :data_fim
            ORDER BY campo_chave ASC, data_registro ASC
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $dataByCampo = [];

        foreach ($rows as $r) {
            $campo = trim($r['campo_chave'] ?? '');
            if ($campo === '') continue;

            // Converter valor
            $valor = $r['valor_lido'];
            if (is_numeric($valor)) {
                $valor = (float)str_replace(',', '.', $valor);
            }

            $entry = [
                'data_registro' => $r['data_registro'],
                'valor_lido' => $valor,
                'unidade_medida' => $r['unidade_medida'],
                'limite_inferior' => $r['limite_inferior'] !== null ? (float)$r['limite_inferior'] : null,
                'limite_superior' => $r['limite_superior'] !== null ? (float)$r['limite_superior'] : null,
                'observacoes' => $r['observacoes'] ?? null
            ];

            // Agrupar
            if (!isset($dataByCampo[$campo])) $dataByCampo[$campo] = [];
            $dataByCampo[$campo][] = $entry;
        }

        $sinais_vitais = [];
        $exames_laboratoriais = [];

        foreach ($dataByCampo as $campo => $registros) {
            usort($registros, fn($a,$b) => strtotime($a['data_registro']) - strtotime($b['data_registro']));
            $ultimo = end($registros);
            reset($registros);

            // Aplicar novos limites conforme idade
            $low = $ultimo['limite_inferior'];
            $high = $ultimo['limite_superior'];

            if ($idadeAnos !== null) {
                $campoLower = strtolower($campo);

                if (strpos($campoLower, 'frequ') !== false && strpos($campoLower, 'card') !== false) {
                    [$low, $high] = limitesFC($idadeAnos, $idadeMeses);
                }
                if (strpos($campoLower, 'frequ') !== false && strpos($campoLower, 'resp') !== false) {
                    [$low, $high] = limitesFR($idadeAnos, $idadeMeses);
                }
                if (strpos($campoLower, 'spo') !== false || strpos($campoLower, 'oxi') !== false) {
                    [$low, $high] = limitesSpO2($idadeAnos);
                }
                if (strpos($campoLower, 'press') !== false) {
                    [$lowSis, $highSis] = limitesPA_sistolica($idadeAnos);
                    [$lowDia, $highDia] = limitesPA_diastolica($idadeAnos);

                    // armazenar limites separados
                    $low = $lowSis . '/' . $lowDia;
                    $high = $highSis . '/' . $highDia;
                }
                // Temperatura (oral/axilar)
                if (strpos($campoLower, 'temp') !== false) {
                    [$low, $high] = limitesTemp($idadeAnos, $idadeMeses);
                }
            }

            $item = [
                'campo' => $campo,
                'registros' => $registros,
                'ultimo_valor' => $ultimo['valor_lido'],
                'ultima_data' => $ultimo['data_registro'],
                'unidade_medida' => $ultimo['unidade_medida'],
                'limite_inferior' => $low,
                'limite_superior' => $high
            ];

            // Identificar sinais vitais
            $isVital = false;
            $vitals = ['freq', 'fc', 'spo', 'oxi', 'temp', 'press'];

            foreach ($vitals as $v) {
                if (stripos($campo, $v) !== false) {
                    $isVital = true; break;
                }
            }

            if ($isVital) $sinais_vitais[$campo] = $item;
            else $exames_laboratoriais[$campo] = $item;
        }


        json([
            'success' => true,
            'data' => [
                'sinais_vitais' => $sinais_vitais,
                'exames_laboratoriais' => $exames_laboratoriais
            ]
        ]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-exams-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de exames: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para procedimentos, consultas e agenda de exames
if ($action === 'get-procedures-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    // Define período padrão (últimos 6 meses)
    if (empty($dataInicio) || empty($dataFim)) { // *** CORREÇÃO DE SINTAXE APLICADA AQUI ***
        $dataFim = date('Y-m-d');
        $dataInicio = date('Y-m-d', strtotime('-6 months'));
    }
    
    try {
        // Buscar todos os agendamentos no período
        $stmt = $pdo->prepare("
            SELECT
                agendamento_id,
                data_consulta,
                hora_consulta,
                tipo,
                descricao,
                local,
                profissional_contato,
                telefone_clinica,
                instrucoes_preparo,
                status,
                status_pagador,
                jejum,
                data_atualizacao
            FROM AGENDA_EXAM_CON_PROC
            WHERE paciente_id = :pid
                AND data_consulta BETWEEN :data_inicio AND :data_fim
            ORDER BY data_consulta DESC, hora_consulta DESC
        ");
        $stmt->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        
        $agendamentos = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Estatísticas
        $totalConsultas = 0;
        $totalExames = 0;
        $totalProcedimentos = 0;
        $realizados = 0;
        $cancelados = 0;
        
        foreach ($agendamentos as $ag) {
            switch ($ag['tipo']) {
                case 'Consulta':
                    $totalConsultas++;
                    break;
                case 'Exame':
                    $totalExames++;
                    break;
                case 'Procedimento':
                    $totalProcedimentos++;
                    break;
            }
            
            if ($ag['status'] === 'Realizado com Sucesso') {
                $realizados++;
            } elseif (in_array($ag['status'], ['Cancelado', 'Não Realizado'])) {
                $cancelados++;
            }
        }
        
        json([
            'success' => true,
            'data' => [
                'agendamentos' => $agendamentos,
                'estatisticas' => [
                    'total_consultas' => $totalConsultas,
                    'total_exames' => $totalExames,
                    'total_procedimentos' => $totalProcedimentos,
                    'realizados' => $realizados,
                    'cancelados' => $cancelados,
                    'total' => count($agendamentos)
                ],
                'periodo' => [
                    'inicio' => $dataInicio,
                    'fim' => $dataFim
                ]
            ]
        ]);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-procedures-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de procedimentos: ' . $e->getMessage()]);
    }
    exit;
}

// Endpoint para conquistas
if ($action === 'get-achievements-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    if (!$pacienteId) {
        json(['success' => false, 'message' => 'paciente_id é obrigatório.']);
        exit;
    }
    try {
        // 1. Buscar dados do paciente
        $stmt = $pdo->prepare("
            SELECT
                survivalProbability,
                tasksCompleted,
                taskProgress,
                updated_at
            FROM patients
            WHERE id = :pid
            LIMIT 1
        ");
        $stmt->execute([':pid' => $pacienteId]);
        $paciente = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$paciente) {
            json(['success' => false, 'message' => 'Paciente não encontrado.']);
            exit;
        }
        
        // 2. Calcular conquistas baseadas em dados reais
        $conquistas = [];
        
        // Compliance de Medicação (últimos 7 dias)
        $stmtCompliance = $pdo->prepare("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'realizada' THEN 1 ELSE 0 END) as realizadas
            FROM agenda_medicamentos
            WHERE paciente_id = :pid
                AND data_hora_agendada >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                AND status IS NOT NULL
        ");
        
        $stmtCompliance->execute([':pid' => $pacienteId]);
        $compliance = $stmtCompliance->fetch(PDO::FETCH_ASSOC);
        
        if ($compliance && $compliance['total'] > 0) {
            $percentualCompliance = ($compliance['realizadas'] / $compliance['total']) * 100;
            
            if ($percentualCompliance >= 95) {
                $conquistas[] = [
                    'icone' => '🏅',
                    'titulo' => '7 Dias de Compliance Perfeito',
                    'descricao' => '>95% de adesão à medicação na última semana.',
                    'cor' => 'bg-green-100'
                ];
            }
        }
        
        // Meta Hídrica (última semana) - QUERY CORRIGIDA
        $stmtHidratacao = $pdo->prepare("
            SELECT AVG(daily_total) as media_diaria
            FROM (
                SELECT SUM(value_1) as daily_total
                FROM diary
                WHERE paciente_id = :pid
                    AND action_type = 'meds'
                    AND unit_1 = 'ml'
                    AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(created_at)
            ) as daily_totals
        ");
        
        $stmtHidratacao->execute([':pid' => $pacienteId]);
        $hidratacao = $stmtHidratacao->fetch(PDO::FETCH_ASSOC);
        
        if ($hidratacao && $hidratacao['media_diaria'] >= 2000) {
            $conquistas[] = [
                'icone' => '💧',
                'titulo' => 'Meta Hídrica da Semana',
                'descricao' => 'Hidratação acima da meta diária (2L).',
                'cor' => 'bg-blue-100'
            ];
        }
        
        // Mobilidade (fisioterapia nos últimos 5 dias)
        $stmtFisio = $pdo->prepare("
            SELECT COUNT(DISTINCT DATE(created_at)) as dias_ativos
            FROM diary
            WHERE paciente_id = :pid
                AND action_type = 'physio'
                AND created_at >= DATE_SUB(NOW(), INTERVAL 5 DAY)
        ");
        
        $stmtFisio->execute([':pid' => $pacienteId]);
        $fisio = $stmtFisio->fetch(PDO::FETCH_ASSOC);
        
        if ($fisio && $fisio['dias_ativos'] >= 5) {
            $conquistas[] = [
                'icone' => '🏃‍♀️',
                'titulo' => '5 Dias Ativo',
                'descricao' => 'Realizou atividades físicas/fisioterapia por 5 dias consecutivos.',
                'cor' => 'bg-purple-100'
            ];
        }
        
        // Cuidador Nota 10 (probabilidade de cura > 90%)
        if ($paciente['survivalProbability'] >= 90) {
            $conquistas[] = [
                'icone' => '🌟',
                'titulo' => 'Cuidador Nota 10',
                'descricao' => 'Probabilidade de recuperação acima de 90%.',
                'cor' => 'bg-yellow-100'
            ];
        }
        
        json([
            'success' => true,
            'data' => [
                'conquistas' => $conquistas,
                'estatisticas' => [
                    'survival_probability' => (float)$paciente['survivalProbability'],
                    'tasks_completed' => (int)$paciente['tasksCompleted'],
                    'task_progress' => (int)$paciente['taskProgress'],
                    'ultima_atualizacao' => $paciente['updated_at']
                ]
            ]
        ]);
    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-achievements-data): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar conquistas: ' . $e->getMessage()]);
    }
    exit;
}

// balanço hídrico
if ($action === 'get-hydric-balance') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    
    if (!$pacienteId || !$dataInicio || !$dataFim) {
        json(['success' => false, 'message' => 'Parâmetros de período e paciente são obrigatórios.']);
        exit;
    }

    try {
        // Contar o número total de dias no período
        $date1 = new DateTime(explode(' ', $dataInicio)[0]); // Considera apenas a data
        $date2 = new DateTime(explode(' ', $dataFim)[0]);
        $diff = $date1->diff($date2);
        // Soma 1 para incluir o dia final. Se for o mesmo dia, days é 0, resulta em 1.
        $totalPeriodDays = $diff->days + 1; 

        // 1. ENTRADAS E SAÍDAS ORAIS (Usando a tabela diary)
        // action_type: 'fluid_intake' (entrada oral) ou 'excretion' (saída)
        $sqlDiary = "
            SELECT 
                action_type, 
                created_at AS data_registro, 
                -- 🔑 CORREÇÃO CRÍTICA: Assume que 'value_1' é a coluna de volume líquido (em mL) 
                -- tanto para entradas ('food', 'meds') quanto para saídas ('excretion').
                value_1 AS volume_ml, 
                value_2,
                unit_2, 
                notes
            FROM diary 
            WHERE paciente_id = :pid 
            AND created_at BETWEEN :data_inicio AND :data_fim
            -- action_type para Entradas ('food', 'meds') e Saídas ('excretion')
            AND action_type IN ('food', 'meds', 'excretion')
            -- Se necessário, adicione uma verificação de unidade: 
            -- AND unit_1 = 'ml'
            ORDER BY created_at ASC
        ";
        $stmtDiary = $pdo->prepare($sqlDiary);
        $stmtDiary->execute([':pid' => $pacienteId, ':data_inicio' => $dataInicio, ':data_fim' => $dataFim]);
        $diaryEntries = $stmtDiary->fetchAll(PDO::FETCH_ASSOC);           
        
        // Filtra e REINDEXA imediatamente usando array_values()
        $oralIntakeList = array_values(array_filter($diaryEntries, fn($e) => in_array($e['action_type'], ['food', 'meds']))); 

        // Filtra e REINDEXA imediatamente usando array_values()
        $excretionList = array_values(array_filter($diaryEntries, fn($e) => $e['action_type'] === 'excretion')); 

        $totalOralIntake = array_sum(array_column($oralIntakeList, 'volume_ml'));
        $totalExcretion = array_sum(array_column($excretionList, 'volume_ml'));


        // 2. ENTRADAS IV/ENTERAL/PARENTERAL (Volume de Medicamentos)
        $sqlMeds = "
            SELECT 
                ag.data_hora_realizada AS data_agendada, 
                1 AS quantidade_aplicacoes,
                (
                    COALESCE(mp.volume_diluicao_quant, 0) + 
                    CASE 
                        WHEN mp.unidade_dosagem = 'ml' THEN COALESCE(mp.dosagem, 0) 
                        ELSE 0 
                    END
                ) AS volume_por_aplicacao,
                ag.observacoes as notes
            FROM agenda_medicamentos ag
            JOIN medicamentos_prescritos mp ON ag.medicamento_id = mp.id
            WHERE ag.paciente_id = :pid
            AND ag.data_hora_realizada BETWEEN :data_inicio AND :data_fim 
            AND ag.data_hora_realizada IS NOT NULL
            AND ag.status = 'realizada'
        ";
        $stmtMeds = $pdo->prepare($sqlMeds);
        $stmtMeds->execute([':pid' => $pacienteId, ':data_inicio' => $dataInicio, ':data_fim' => $dataFim]);
        $medsData = $stmtMeds->fetchAll(PDO::FETCH_ASSOC);

        $ivIntakeList = [];
        $totalIvIntake = 0;

        foreach ($medsData as $med) {
            
            // 🔑 CORREÇÃO: Usar o campo calculado 'volume_por_aplicacao'
            $volumePorAplicacao = (float)$med['volume_por_aplicacao']; 
    
            // Calcula o volume total (volume por aplicação * quantidade de aplicações)
            $totalVolume = $med['quantidade_aplicacoes'] * $volumePorAplicacao;
            
            if ($totalVolume > 0) {
                // Adicionar rótulo para diferenciar na tabela do front
                $med['tipo'] = 'IV/Enteral (Medicação)'; 
                $med['volume_ml'] = $totalVolume;
                $ivIntakeList[] = $med;
                $totalIvIntake += $totalVolume;
            }
        }

        // 3. PERDAS INSENSÍVEIS (Estimação por dias de febre)
        $sqlVitals = "
            SELECT valor_lido, data_registro 
            FROM sinais_vitais_exames
            WHERE paciente_id = :pid 
            AND campo_chave = 'Temperatura'
            AND data_registro BETWEEN :data_inicio AND :data_fim
            ORDER BY data_registro ASC
        ";
        $stmtVitals = $pdo->prepare($sqlVitals);
        $stmtVitals->execute([':pid' => $pacienteId, ':data_inicio' => $dataInicio, ':data_fim' => $dataFim]);
        $vitalsData = $stmtVitals->fetchAll(PDO::FETCH_ASSOC);
        
        $totalFeverDays = 0;
        $processedDates = [];
        
        // Conta dias distintos com temperatura máxima > 37.8°C (Febre)
        foreach ($vitalsData as $vital) {
            $dateOnly = date('Y-m-d', strtotime($vital['data_registro']));
            if (!isset($processedDates[$dateOnly]) && (float)$vital['temperatura'] > 37.8) {
                $processedDates[$dateOnly] = true;
                $totalFeverDays++;
            }
        }
        
        // CÁLCULO DA PERDA INSENSÍVEL
        // 500 mL/24h (mínimo) + 200 mL/24h (média) + 150 mL/24h por dia de febre
        $basalLossPerDay = 700; 
        $feverLossPerDay = 150; 
        
        $totalBasalLoss = $basalLossPerDay * $totalPeriodDays; 
        $totalFeverLoss = $feverLossPerDay * $totalFeverDays;
        $totalInsensibleLoss = $totalBasalLoss + $totalFeverLoss;


        json([
            'success' => true, 
            'data' => [
                'period_days' => $totalPeriodDays,
                'total_oral_intake_ml' => (float)number_format($totalOralIntake, 2, '.', ''),
                'total_iv_intake_ml' => (float)number_format($totalIvIntake, 2, '.', ''),
                'total_excretion_ml' => (float)number_format($totalExcretion, 2, '.', ''),
                'total_insensible_loss_ml' => (float)number_format($totalInsensibleLoss, 2, '.', ''),
                'fever_days' => $totalFeverDays,
                'intake_details' => array_merge($oralIntakeList, $ivIntakeList), 
                'excretion_details' => $excretionList,
            ]
        ]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-hydric-balance): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de balanço hídrico: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Lógica para 'get-meal-balance'   
if ($action === 'get-meal-balance') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    
    if (!$pacienteId || !$dataInicio || !$dataFim) {
        json(['success' => false, 'message' => 'Parâmetros de período e paciente são obrigatórios.']);
        exit;
    }

    try {
        // Query para obter o total diário de comida (value_1 em 'food') e fezes (value_2 em 'excretion')
       $sql = "
            SELECT 
                DATE(created_at) as dia,
                -- Total de entrada: aceita 'g' e 'unitG'
                SUM(CASE 
                    WHEN action_type = 'food' AND unit_1 IN ('g', 'unitG') 
                    THEN COALESCE(value_1, 0) 
                    ELSE 0 
                END) as total_intake_g,
                
                -- Total de saída (Fezes): aceita 'g' e 'unitG' em unit_2
                SUM(CASE 
                    WHEN action_type = 'excretion' AND unit_2 IN ('g', 'unitG') 
                    THEN COALESCE(value_2, 0) 
                    ELSE 0 
                END) as total_output_g
            FROM diary 
            WHERE paciente_id = :pid 
            AND created_at BETWEEN :data_inicio AND :data_fim
            AND action_type IN ('food', 'excretion')
            GROUP BY dia
            ORDER BY dia ASC
        ";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':pid' => $pacienteId, 
            ':data_inicio' => $dataInicio, 
            ':data_fim' => $dataFim
        ]);
        
        $dailyData = $stmt->fetchAll(PDO::FETCH_ASSOC);

        json([
            'success' => true, 
            'data' => $dailyData
        ]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-meal-balance): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar dados de balanço nutricional: ' . $e->getMessage()]);
    }
    exit;
}

// api.php - Lógica para 'get-medication-summary' 
if ($action === 'get-medication-summary') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? null;
    $dataFim = $_GET['data_fim'] ?? null;
    
    if (!$pacienteId || !$dataInicio || !$dataFim) {
        json(['success' => false, 'message' => 'Parâmetros obrigatórios ausentes.']);
        exit;
    }

    try {
       
        // Query para contar o total de doses realizadas por medicamento/dosagem no período
        $sqlSummary = "
            SELECT 
                mp.nome_medicamento,
                mp.dosagem,
                mp.unidade_dosagem,
                COUNT(ag.id) AS total_doses
            FROM agenda_medicamentos ag
            JOIN medicamentos_prescritos mp ON ag.medicamento_id = mp.id
            WHERE ag.paciente_id = :pid
            AND ag.data_hora_realizada BETWEEN :data_inicio AND :data_fim
            AND ag.data_hora_realizada IS NOT NULL -- Apenas doses aplicadas
            GROUP BY mp.nome_medicamento, mp.dosagem, mp.unidade_dosagem
            ORDER BY total_doses DESC
        ";
        
        $stmt = $pdo->prepare($sqlSummary);
        $stmt->execute([
            ':pid' => $pacienteId, 
            ':data_inicio' => $dataInicio, 
            ':data_fim' => $dataFim
        ]);
        
        $summary = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Garantir que a lista seja um array sequencial (JSON Array)
        $summary = array_values($summary);

        json([
            'success' => true, 
            'data' => $summary
        ]);

    } catch (PDOException $e) {
        error_log("❌ EXCEÇÃO PDO (get-medication-summary): " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro ao buscar resumo de medicamentos: ' . $e->getMessage()]);
    }
    exit;
}

// calcula adesão à prescrição médica de medicamentos
if ($action === 'get-medication-compliance') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? date('Y-m-d 00:00:00');
    $dataFim    = $_GET['data_fim'] ?? date('Y-m-d 23:59:59');

    if (!$pacienteId) {
        json(['success' => false, 'message' => 'ID do paciente obrigatório']);
        exit; // Importante: garantir que pare aqui
    }

    try {
        // 1. NUMERADOR: Total de doses REALMENTE administradas no período
        $sqlRealizadas = "
            SELECT COUNT(*) as total_realizado 
            FROM agenda_medicamentos 
            WHERE paciente_id = :pid 
            AND data_hora_realizada BETWEEN :data_inicio AND :data_fim
            AND data_hora_realizada IS NOT NULL
        ";
        
        // --- CORREÇÃO: Preparar e Executar a query do Numerador ---
        $stmtReal = $pdo->prepare($sqlRealizadas);
        $stmtReal->execute([':pid' => $pacienteId, ':data_inicio' => $dataInicio, ':data_fim' => $dataFim]);
        $resReal = $stmtReal->fetch(PDO::FETCH_ASSOC);
        $totalRealizado = $resReal ? (int)$resReal['total_realizado'] : 0;

        // 2. DENOMINADOR: Cálculo Teórico (Prescrições)
        // --- CORREÇÃO: Definir a variável $sqlPrescricoes antes de usar ---
        $sqlPrescricoes = "
            SELECT data_hora_inicio, intervalo_horas 
            FROM medicamentos_prescritos 
            WHERE paciente_id = :pid
        ";

        $stmtPresc = $pdo->prepare($sqlPrescricoes);
        $stmtPresc->execute([':pid' => $pacienteId]);
        $prescricoes = $stmtPresc->fetchAll(PDO::FETCH_ASSOC);

        $totalEsperado = 0;
        $dtInicioFiltro = new DateTime($dataInicio);
        $dtFimFiltro    = new DateTime($dataFim);
        $agora          = new DateTime();

        // Trava de futuro: se o filtro for até o fim do mês, calculamos esperado apenas até AGORA.
        $fimCalculoEfetivo = ($dtFimFiltro > $agora) ? $agora : $dtFimFiltro;

        foreach ($prescricoes as $p) {
            // Validação de segurança se o intervalo for nulo ou zero
            if (empty($p['intervalo_horas']) || $p['intervalo_horas'] <= 0) continue;

            // Verifica se a coluna data_hora_inicio veio corretamente
            // Tenta 'data_hora_inicio', se não existir tenta 'data_inicio' (compatibilidade)
            $colunaData = $p['data_hora_inicio'] ?? $p['data_inicio'] ?? null;
            
            if (!$colunaData) continue; 

            $dtInicioPrescricao = new DateTime($colunaData);
            
            // O início da contagem é o maior valor entre: Início do Filtro vs Início da Prescrição
            $inicioCalculo = ($dtInicioPrescricao > $dtInicioFiltro) ? $dtInicioPrescricao : $dtInicioFiltro;

            // Se a prescrição começou depois do período de análise, ignora
            if ($inicioCalculo >= $fimCalculoEfetivo) continue;

            // Diferença em horas
            $segundosDiff = $fimCalculoEfetivo->getTimestamp() - $inicioCalculo->getTimestamp();
            $horasTotais = $segundosDiff / 3600;

            if ($horasTotais > 0) {
                $totalEsperado += floor($horasTotais / $p['intervalo_horas']);
            }
        }

        // 3. Percentual
        $percentual = 0;
        if ($totalEsperado > 0) {
            $percentual = ($totalRealizado / $totalEsperado) * 100;
            if ($percentual > 100) $percentual = 100;
        } else {
            // Se não havia expectativa e tomou (ou não), considera 100% ou 0% dependendo da regra
            // Aqui: se realizou algo sem esperar = 100%, se não fez nada e não esperava nada = 100%
            $percentual = 100;
        }

        json([
            'success' => true,
            'compliance' => [
                'realizado' => $totalRealizado,
                'esperado'  => (int)$totalEsperado,
                'percentual' => round($percentual, 1)
            ]
        ]);

    } catch (PDOException $e) {
        error_log("Erro Compliance SQL: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro SQL: ' . $e->getMessage()]);
    }
    exit;
}

// Consulta interações medicamentosas
/* ============================================================
   ENDPOINT: check-ddi
   Entrada:
     {
       "paciente_id": 44,
       "meds": "paracetamol; ibuprofeno",
       "lang": "pt"
     }
   ============================================================ */
if ($action === 'check-ddi') {
    try {

        // ========= 1) Validar entrada =========
        $paciente_id = intval($input['paciente_id'] ?? 0);
        if ($paciente_id <= 0) {
            json(['success'=>false,'message'=>'paciente_id inválido']);
        }

        if (!empty($input['meds']) && is_string($input['meds'])) {
            $raw = preg_split('/[;\r\n,]+/', $input['meds']);
            $meds = array_map('trim', array_filter($raw));
        } elseif (!empty($input['meds']) && is_array($input['meds'])) {
            $meds = array_map('trim', array_filter($input['meds']));
        } else {
            json(['success'=>false,'message'=>'Envie "meds" como string ou lista']);
        }

        $lang = strtolower($input['lang'] ?? 'auto');
        if (!in_array($lang,['auto','pt','en','es'])) $lang='auto';

        // ========= 2) Tradução (somente nomes, para a consulta) =========

         // usando tradutores online
        function translate_libre($text, $target = 'en') {
            $url = LIBRETRANSLATE_URL;
            $data = [
                'q' => $text,
                'source' => 'auto',
                'target' => $target,
                'format' => 'text'
            ];
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                CURLOPT_POSTFIELDS => json_encode($data),
                CURLOPT_TIMEOUT => 15,
            ]);
            $resp = curl_exec($ch);
            $err = curl_error($ch);
            curl_close($ch);

            if ($err) {
                error_log("translate_libre error: $err");
                return $text;
            }
            $j = json_decode($resp, true);
            return $j['translatedText'] ?? $text;
        }

        function translate_if_needed($text, $target = 'en') {
            // se Google presente, use Google, senão LibreTranslate
            if (!empty(GOOGLE_TRANSLATE_KEY)) {
                // sua lógica original de Google
                // … (mantém o que você tinha)
            } else {
                return translate_libre($text, $target);
            }
        }

        /* 
        // traduzindo nomes de medicamentos para inglês
        $translated_map = [];
        foreach ($meds as $m) {
            $translated_map[$m] = translate_if_needed($m, 'en');
        }
        */

        // ========= 2) Tradução (via Banco de Dados - tb_produtos) =========

        $translated_map = [];
        $pdoMed = null;

        // Tenta conectar ao banco de medicamentos
        try {
            // Defina as credenciais. Se estiverem no config.php, use as constantes.
            // Caso contrário, preencha abaixo:

            $dbHost = DB_MED_HOST ;
            $dbName = DB_MED_NAME ;
            $dbUser = DB_MED_USER ; 
            $dbPass = DB_MED_PASS ; 

            $pdoMed = new PDO("mysql:host=$dbHost;dbname=$dbName;charset=utf8mb4", $dbUser, $dbPass);
            $pdoMed->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        } catch (PDOException $e) {
            // Se falhar a conexão, o sistema apenas avisa no log e usará os nomes originais
            error_log("Aviso check-ddi: Não foi possível conectar ao banco de traduções. " . $e->getMessage());
        }

        foreach ($meds as $m) {
            $termo_ingles = $m; // Começa com o original
            $encontrado = false;

            if ($pdoMed) {
                try {
                    // TENTATIVA 1: Busca Exata (tb_produtos no PLURAL)
                    $stmt = $pdoMed->prepare("SELECT nome_en_search FROM tb_produto WHERE nome_pt = :nome LIMIT 1");
                    $stmt->execute([':nome' => trim($m)]);
                    $res = $stmt->fetch(PDO::FETCH_ASSOC);

                    if ($res && !empty($res['nome_en_search'])) {
                        $termo_ingles = $res['nome_en_search'];
                        $encontrado = true;
                    } else {
                        // TENTATIVA 2: Busca Aproximada
                        $stmt = $pdoMed->prepare("SELECT nome_en_search FROM tb_produto WHERE nome_pt LIKE :nome LIMIT 1");
                        $stmt->execute([':nome' => trim($m) . '%']);
                        $res = $stmt->fetch(PDO::FETCH_ASSOC);
                        
                        if ($res && !empty($res['nome_en_search'])) {
                            $termo_ingles = $res['nome_en_search'];
                            $encontrado = true;
                        }
                    }
                } catch (Exception $ex) {
                    error_log("Erro SQL tradução ($m): " . $ex->getMessage());
                }
            }
            
            // TENTATIVA 3: Fallback API (Se não achou no banco)
            if (!$encontrado) {
                // CORREÇÃO CRÍTICA AQUI: Passamos '$m' e não '$res' (que estaria vazio)
                $termo_ingles = translate_if_needed($m, 'en'); 
            }
            
            $translated_map[$m] = $termo_ingles;
        }


        // ========= 3) Helpers DrugBank =========

        function api_drugbank_get($endpoint, $params=[]) {
            $url = DRUGBANK_BASE . $endpoint;
            $q = $params ? ('?' . http_build_query($params)) : '';

            $ch = curl_init($url . $q);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => [
                    'authorization: ' . DRUGBANK_API_KEY,
                    'Accept: application/json'
                ],
                CURLOPT_TIMEOUT => 20
            ]);
            $resp = curl_exec($ch);
            $err = curl_error($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            return [$code,$resp,$err];
        }

        // ========= 4) Obter DBPC IDs (COM DEBUG DETALHADO) =========

        $product_ids = [];
        $not_found = [];
        $debug_api_responses = []; // <--- Novo array para capturar respostas da API

        foreach ($translated_map as $orig => $tr) {
            // Chamada à API
            list($code, $body, $err) = api_drugbank_get('/product_concepts', ['q' => $tr, 'limit' => 5]);
            
            // Decodifica para verificar erros no JSON também
            $j = json_decode($body, true);

            // LOG DE DEBUG: Guarda o que aconteceu nesta requisição específica
            $debug_api_responses[] = [
                'termo_pesquisado' => $tr,
                'http_code' => $code,
                'curl_error' => $err,
                'response_body' => $j ?? $body // Salva o JSON decodificado ou a string bruta
            ];

            // Verificação de falha
            if ($err || $code !== 200) {
                $not_found[] = $orig;
                continue;
            }

            $found = false;
            if (!empty($j['data'])) {
                foreach ($j['data'] as $row) {
                    if (!empty($row['id']) && strpos($row['id'], 'DBPC') === 0) {
                        $product_ids[] = $row['id'];
                        $found = true;
                        break;
                    }
                }
            }
            
            if (!$found) $not_found[] = $orig;
            
            // Delay (importante manter)
            usleep(100000); 
        }

        // Se falhar (nenhum ID encontrado), retorna o JSON com o DEBUG
        if (!$product_ids) {
            json([
                'success' => false,
                'message' => 'Este recurso está temporariamente indisponível. Tente novamente mais tarde.',
                'not_found' => $not_found,
                'meds_checked_en' => array_values($translated_map),
                'debug_drugbank' => $debug_api_responses // <--- AQUI ESTÁ A CHAVE DO MISTÉRIO
            ]);
            exit; 
        }

        // ========= 5) Consultar DDI =========

        list($code2,$body2,$err2) = api_drugbank_get('/ddi',[
            'product_concept_id'=>implode(',',array_unique($product_ids))
        ]);

        if ($err2 || $code2!==200) {
            json(['success'=>false,'message'=>'Erro DrugBank DDI','code'=>$code2,'err'=>$err2,'body'=>$body2]);
        }

        $ddi_json = json_decode($body2,true);
        $interactions = $ddi_json['interactions'] ?? [];

        // ========= 6) Consolidar ALERTAS =========

        $alert_text = "";
        $worst_grade = "desconhecido";

        $severity_order = [
            "contraindicated" => 4,
            "contra-indicado" => 4,
            "major" => 3,
            "moderate" => 2,
            "minor" => 1
        ];

        foreach ($interactions as $it) {
            $drugA = $it['drug1']['name'] ?? '?';
            $drugB = $it['drug2']['name'] ?? '?';
            $sev   = strtolower($it['severity'] ?? 'unknown');
            $desc  = $it['description'] ?? json_encode($it);

            // determinar pior gravidade
            if (isset($severity_order[$sev])) {
                if (!isset($severity_order[$worst_grade]) || 
                    $severity_order[$sev] > $severity_order[$worst_grade]) {
                    $worst_grade = $sev;
                }
            }

            $alert_text .= "Interação entre $drugA e $drugB: $desc\n\n";
        }

        if (!$alert_text) $alert_text = "Nenhuma interação encontrada.";

        // ========= 7) Traduzir texto consolidado para o idioma do cuidador =========

        if ($lang !== 'en' && $lang !== 'auto') {
            $alert_text = translate_if_needed($alert_text, $lang);
            if (isset($severity_order[$worst_grade]) && $lang==='pt') {
                if ($worst_grade==='contraindicated') $worst_grade='contra-indicado';
            }
        }

        // ========= 8) SALVAR NO BANCO =========

        $lista_original   = implode("; ", $meds);
        $lista_traduzida  = implode("; ", array_values($translated_map));

        $sql = "INSERT INTO alertas_medicamentos
                (paciente_id, lista_medicamentos, lista_medicamentos_trad,
                 data_hora_consulta, data_atualizacao,
                 descricao_alerta, gravidade, origem, raw_payload,
                 created_at)
                VALUES
                (:pid, :orig, :trad, NOW(), NOW(),
                 :desc, :grav, 'DrugBank', :raw, NOW())";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':pid'  => $paciente_id,
            ':orig' => $lista_original,
            ':trad' => $lista_traduzida,
            ':desc' => $alert_text,
            ':grav' => $worst_grade,
            ':raw'  => json_encode($ddi_json)
        ]);

        $insert_id = $pdo->lastInsertId();

        // ========= 9) Retornar resposta =========

        json([
            'success'=>true,
            'alerta_id'=>$insert_id,
            'paciente_id'=>$paciente_id,
            'lista_medicamentos'=>$lista_original,
            'lista_medicamentos_trad'=>$lista_traduzida,
            'gravidade'=>$worst_grade,
            'descricao_alerta'=>$alert_text,
            'not_found'=>$not_found,
            'drugbank_raw'=>$ddi_json
        ]);

    } catch (Exception $e) {
        error_log("ERRO check-ddi: ".$e->getMessage());
        json(['success'=>false,'message'=>$e->getMessage()]);
    }
}

// 1. AÇÃO DE REGISTRAR INÍCIO (ATUALIZADA)
if ($action === 'registrar-inicio-infusao') {
    try {
        $id = $input['id'] ?? null;
        $dataPrevista = $input['data_hora_final_previsto'] ?? null;
        $volume = $input['volume_infusao'] ?? null; // Novo
        $vazao = $input['vazao_infusao'] ?? null;   // Novo

        if ($id && $dataPrevista) {
            // Atualiza data final, volume e vazão
            $stmt = $pdo->prepare("
                UPDATE agenda_medicamentos 
                SET data_hora_final_previsto = :data,
                    volume_infusao = :vol,
                    vazao_infusao = :vazao,
                    updated_at = NOW()
                WHERE id = :id
            ");
            
            $stmt->execute([
                ':data' => $dataPrevista,
                ':vol' => $volume,
                ':vazao' => $vazao,
                ':id' => $id
            ]);
            
            json(['success' => true]);
        } else {
            json(['success' => false, 'error' => 'Dados incompletos (ID ou Data faltantes)']);
        }
    } catch (Exception $e) {
        json(['success' => false, 'error' => $e->getMessage()]);
    }
}

// 2. AÇÃO DE BUSCAR ATIVAS (ATUALIZADA)
if ($action === 'buscar-infusoes-ativas') {
    try {
        $pacienteId = $_GET['pacienteId'] ?? $input['pacienteId'] ?? null;

        if ($pacienteId) {
            // Adicionado volume_infusao e vazao_infusao na query
            $stmt = $pdo->prepare("
                SELECT 
                    id, 
                    nome_medicamento, 
                    dosagem, 
                    unidade_dosagem, 
                    data_hora_final_previsto,
                    volume_infusao,
                    vazao_infusao
                FROM agenda_medicamentos 
                WHERE paciente_id = :pid 
                  AND data_hora_final_previsto IS NOT NULL 
                  AND (observacoes IS NULL OR observacoes = '')
            ");
            $stmt->execute([':pid' => $pacienteId]);
            $infusoes = $stmt->fetchAll(PDO::FETCH_ASSOC);
            json(['success' => true, 'data' => $infusoes]);
        } else {
            json(['success' => false, 'error' => 'Paciente ID necessário']);
        }
    } catch (Exception $e) {
        json(['success' => false, 'error' => $e->getMessage()]);
    }
}

// gameficação
/* --- api.php --- */    
if ($action === 'get-gamification-data') {
    $pacienteId = $_GET['paciente_id'] ?? null;
    $caregiverId = $_GET['caregiver_id'] ?? null;
    $dataInicio = $_GET['data_inicio'] ?? date('Y-m-d 00:00:00');
    $dataFim    = $_GET['data_fim'] ?? date('Y-m-d 23:59:59');

    if (!$pacienteId) {
        json(['success' => false, 'message' => 'ID do Paciente é obrigatório.']);
        exit;
    }

    try {
        // --- PARTE 1: Estatísticas usando APENAS as tabelas confirmadas no seu api.php ---
        $sqlStats = "
            SELECT 
                -- NOVA: DIVULGADOR (Baseado na tabela shares que criamos)
                (SELECT COUNT(*) FROM shares 
                WHERE caregiver_id = :cid 
                AND created_at BETWEEN :data_inicio AND :data_fim) as total_shares,

                -- Medicamentos (Original)
                (SELECT COUNT(*) FROM agenda_medicamentos 
                 WHERE updated_by = :cid AND paciente_id = :pid AND status = 'realizada'
                 AND updated_at BETWEEN :data_inicio AND :data_fim) as meds_administrados,
                
                -- Atividades Físicas (Original)
                (SELECT COUNT(*) FROM diary 
                 WHERE caregiver_id = :cid AND paciente_id = :pid AND action_type = 'physio'
                 AND created_at BETWEEN :data_inicio AND :data_fim) as atividades_fisicas,
                
                -- Higiene/Alimentação (Original)
                (SELECT COUNT(*) FROM diary 
                 WHERE caregiver_id = :cid AND paciente_id = :pid AND action_type IN ('shower','excretion','food')
                 AND created_at BETWEEN :data_inicio AND :data_fim) as higiene_logs,

                 -- MESTRE DA AGENDA (Sua nova consulta)
                (SELECT COUNT(*) FROM AGENDA_EXAM_CON_PROC 
                WHERE paciente_id = :pid 
                AND status = 'Realizado com Sucesso'
                AND data_atualizacao BETWEEN :data_inicio AND :data_fim) as appointments_concluidos,

                -- EXPERT EM BIOSSEGURANÇA (Limpeza de Localizações)
                (SELECT COUNT(*) FROM patient_location_history 
                WHERE patient_id = :pid AND caregiver_id = :cid
                AND last_cleaning_date BETWEEN :data_inicio AND :data_fim) as limpezas_terminais,

                -- CONECTOR DE SAÚDE (Sua nova consulta)
                (SELECT COUNT(*) FROM pending_invites 
                WHERE patient_id = :pid AND invited_by_user_id = :cid
                AND created_at BETWEEN :data_inicio AND :data_fim) as convites_sucesso,

                -- SEGURANÇA FARMACÊUTICA (alertas_medicamentos)
                (SELECT COUNT(*) FROM alertas_medicamentos 
                WHERE paciente_id = :pid 
                AND created_at BETWEEN :data_inicio AND :data_fim) as consultas_interacao,

                -- NOVA: Curativos e Procedimentos (Baseado na tabela de manutenção de cateteres)
                (SELECT COUNT(*) 
                FROM catheter_maintenance_logs cml
                JOIN patient_catheters pc ON cml.catheter_id = pc.id
                WHERE pc.patient_id = :pid 
                AND pc.status = 'ativo'                
                AND cml.realizado_em BETWEEN :data_inicio AND :data_fim
                ) as procedimentos_especiais,

                -- NOVA: Registros de peso, altura e circunferência
                (SELECT COUNT(*) FROM porte_fisico
                 WHERE caregiver_id = :cid AND paciente_id = :pid 
                 AND created_at BETWEEN :data_inicio AND :data_fim) as registros_biometricos,
                
                -- Bem estar e Chat (Originais)
                (SELECT COUNT(*) FROM caregiver_wellness WHERE caregiver_id = :cid AND created_at BETWEEN :data_inicio AND :data_fim) as bem_estar_logs,
                (SELECT COUNT(*) FROM caregiver_chat_messages WHERE sender_id = :cid AND patient_id = :pid AND created_at BETWEEN :data_inicio AND :data_fim) as chat_msgs,

                -- Financeiro
                (SELECT COUNT(*) FROM finance_expenses 
                WHERE caregiver_id = :cid AND patient_id = :pid
                AND criado_em BETWEEN :data_inicio AND :data_fim) as controle_financeiro,

                -- Medalha: Autor de Bestseller (history_posts)
                (SELECT COUNT(*) FROM history_posts 
                WHERE patient_id = :pid AND caregiver_id = :cid
                AND created_at BETWEEN :data_inicio AND :data_fim) as posts_realizados,

                -- Medalha: Estrategista Clínico (decisions)
                (SELECT COUNT(*) FROM decisions 
                WHERE patient_id = :pid AND created_by_caregiver_id = :cid
                AND created_at BETWEEN :data_inicio AND :data_fim) as decisoes_ia,

                -- GUARDIÃO DA EQUIPE
                (SELECT COUNT(*) FROM relatorios_atendimentos 
                WHERE paciente_id = :pid AND user_id = :cid
                AND (profissional_nome IS NOT NULL AND profissional_nome != '')
                AND data_registro BETWEEN :data_inicio AND :data_fim) as registros_equipe 

        ";
        
        $stmtStats = $pdo->prepare($sqlStats);
        $stmtStats->execute([
            ':cid' => $caregiverId ?? 0, 
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio, 
            ':data_fim' => $dataFim
        ]);
        $stats = $stmtStats->fetch(PDO::FETCH_ASSOC);

        if (!$stats) {
            $stats = ['total_shares'=>0,'meds_administrados'=>0,'atividades_fisicas'=>0,'higiene_logs'=>0,'procedimentos_especiais'=>0,'registros_biometricos'=>0,'bem_estar_logs'=>0,'chat_msgs'=>0, 'registros_equipe'=>0];
        }

        // --- PARTE 2: Medalhas (Badges) Baseadas nos dados acima ---
        $badges = [];
        if ($stats['total_shares'] >= 1) $badges[] = ["title" => "Embaixador Acura", "icon" => "🚀", "desc" => "Fortaleceu a rede de apoio compartilhando o app"];
        if ($stats['meds_administrados'] >= 1) $badges[] = ["title" => "Pontualidade", "icon" => "💊", "desc" => "Medicações em dia"];
        if ($stats['procedimentos_especiais'] >= 1) $badges[] = ["title" => "Especialista", "icon" => "🩹", "desc" => "Realizou curativos/procedimentos"];
        if ($stats['atividades_fisicas'] >= 1) $badges[] = ["title" => "Reabilitador", "icon" => "🏃", "desc" => "Foco em mobilidade"];
        if ($stats['registros_biometricos'] >= 1) $badges[] = ["title" => "Vigilante", "icon" => "⚖️", "desc" => "Peso e sinais registrados"];
        if ($stats['chat_msgs'] >= 5) $badges[] = ["title" => "Comunicador", "icon" => "💬", "desc" => "Ativo no chat da equipe"];
        if ($stats['registros_equipe'] >= 1) $badges[] = ["title" => "Guardião da Equipe", "icon" => "🛡️", "desc" => "Integração de profissionais"];


        // Adicionamos ao array para o front-end
        $stats['badges'] = $badges;

        // --- PARTE 3: Ranking de Equipe (XP) ---
        // Usamos APENAS as tabelas existentes para calcular o Ranking
        $sqlRanking = "
            SELECT 
                u.nickname as nome_cuidador, 
                u.id as cuidador_id,
                u.avatarUrl,
                (
                    (COALESCE((SELECT COUNT(*) FROM shares WHERE caregiver_id = u.id AND created_at BETWEEN :data_inicio AND :data_fim), 0) * 30) +
                    (COALESCE((SELECT COUNT(*) FROM agenda_medicamentos WHERE updated_by = u.id AND paciente_id = :pid AND status = 'Realizada'), 0) * 50) +
                    (COALESCE((SELECT COUNT(*) FROM diary WHERE caregiver_id = u.id AND paciente_id = :pid AND action_type = 'physio'), 0) * 40) +
                    (COALESCE((SELECT COUNT(*) FROM diary WHERE caregiver_id = u.id AND paciente_id = :pid AND action_type IN ('dressing','wound','flush')), 0) * 60) +
                    (COALESCE((SELECT COUNT(*) FROM caregiver_chat_messages WHERE sender_id = u.id AND patient_id = :pid), 0) * 5) +
                    (COALESCE((SELECT COUNT(*) FROM relatorios_atendimentos WHERE paciente_id = :pid AND user_id = u.id  AND (profissional_nome IS NOT NULL AND profissional_nome != '')), 0) * 70) 
                ) as total_xp
            FROM patient_caregivers pc
            JOIN users u ON pc.caregiver_id = u.id
            WHERE pc.patient_id = :pid
            ORDER BY total_xp DESC
        ";

        $stmtRank = $pdo->prepare($sqlRanking);
        $stmtRank->execute([
            ':pid' => $pacienteId,
            ':data_inicio' => $dataInicio,
            ':data_fim' => $dataFim
        ]);
        $ranking = $stmtRank->fetchAll(PDO::FETCH_ASSOC);

        $myTotalXp = 0;
        foreach ($ranking as $r) {
            if ($r['cuidador_id'] == $caregiverId) {
                $myTotalXp = $r['total_xp'];
                break;
            }
        }
        $stats['total_xp'] = $myTotalXp;

        json([
            'success' => true,
            'data' => [
                'stats' => $stats,
                'ranking' => $ranking
            ]
        ]);

    } catch (Exception $e) {
        error_log("Erro Gamification: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno: ' . $e->getMessage()]);
    }
}

//notificações push
/* api.php - NOVO ENDPOINT: Verificar itens pendentes para notificação */
if ($action === 'check-due-notifications') {
    $caregiverId = $_GET['caregiverId'] ?? null;
    
    if (!$caregiverId) {
        json(['success' => false, 'message' => 'caregiverId obrigatório']);
    }

    try {
        // 1. Definição do intervalo de tempo (ex: itens agendados entre 30 min atrás e os próximos 20 min)
        // Isso cobre pequenos atrasos e avisos antecipados.
        $now = date('Y-m-d H:i:s');
        $timeStart = date('Y-m-d H:i:s', strtotime('-30 minutes'));
        $timeEnd   = date('Y-m-d H:i:s', strtotime('+20 minutes'));

        $notifications = [];

        // 2. Buscar MEDICAMENTOS Pendentes
        // status IS NULL assume que ainda não foi realizado/baixado
        $sqlMeds = "
            SELECT 
                am.id, 
                am.nome_medicamento as titulo, 
                am.data_hora_agendada as data_hora, 
                p.nickname as paciente,
                'meds' as tipo
            FROM agenda_medicamentos am
            JOIN patient_caregivers pc ON am.paciente_id = pc.patient_id
            JOIN patients p ON am.paciente_id = p.id
            WHERE pc.caregiver_id = :cid
            AND am.status IS NULL
            AND am.data_hora_agendada BETWEEN :start AND :end
        ";
        
        $stmtMeds = $pdo->prepare($sqlMeds);
        $stmtMeds->execute([':cid' => $caregiverId, ':start' => $timeStart, ':end' => $timeEnd]);
        $meds = $stmtMeds->fetchAll(PDO::FETCH_ASSOC);

        foreach($meds as $m) {
            $m['mensagem'] = "Medicamento: " . $m['titulo'] . " (" . date('H:i', strtotime($m['data_hora'])) . ")";
            $notifications[] = $m;
        }

        // 3. Buscar EXAMES, CONSULTAS e PROCEDIMENTOS Pendentes
        // Filtra status que não sejam de conclusão/cancelamento
        $sqlProc = "
            SELECT 
                ag.agendamento_id as id, 
                ag.descricao as titulo, 
                ag.tipo,
                CONCAT(ag.data_consulta, ' ', ag.hora_consulta) as data_hora, 
                p.nickname as paciente,
                'procedimento' as tipo_categ
            FROM AGENDA_EXAM_CON_PROC ag
            JOIN patient_caregivers pc ON ag.paciente_id = pc.patient_id
            JOIN patients p ON ag.paciente_id = p.id
            WHERE pc.caregiver_id = :cid
            AND ag.status NOT IN ('Realizado com Sucesso', 'Cancelado', 'Não Realizado')
            AND CONCAT(ag.data_consulta, ' ', ag.hora_consulta) BETWEEN :start AND :end
        ";

        $stmtProc = $pdo->prepare($sqlProc);
        $stmtProc->execute([':cid' => $caregiverId, ':start' => $timeStart, ':end' => $timeEnd]);
        $procs = $stmtProc->fetchAll(PDO::FETCH_ASSOC);

        foreach($procs as $p) {
            $p['mensagem'] = "{$p['tipo']}: {$p['titulo']} (" . date('H:i', strtotime($p['data_hora'])) . ")";
            $notifications[] = $p;
        }

        json(['success' => true, 'data' => $notifications]);

    } catch (Exception $e) {
        error_log("Erro check-due-notifications: " . $e->getMessage());
        json(['success' => false, 'error' => $e->getMessage()]);
    }
}


/* api.php - Atualizar Localização e Histórico */
if ($action === 'update-patient-location') {
    // Leitura do Body da Requisição (caso não tenha sido feito fora deste if)
    $input = json_decode(file_get_contents('php://input'), true);

    $patientId    = $input['patientId'] ?? null;
    $caregiverId  = $input['caregiverId'] ?? null;
    $hospitalName = $input['hospitalName'] ?? '';
    $sector       = $input['sector'] ?? '';
    $floor        = $input['floor'] ?? '';
    $bed          = $input['bed'] ?? '';
    $admDate      = $input['admissionDate'] ?? null;
    $lat          = $input['lat'] ?? null;
    $lng          = $input['lng'] ?? null;
    
    // [NOVO] Captura a frequência de limpeza (Padrão: 7 dias se não vier no input)
    $cleaningFreq = $input['cleaningFrequency'] ?? 7;

    if (!$patientId) {
        json(['success' => false, 'message' => 'Dados incompletos: falta id paciente.']);
    }
    
    if (!$caregiverId) {
        json(['success' => false, 'message' => 'Dados incompletos: falta id cuidador']);
    }

    try {
        $pdo->beginTransaction();

        // 1. Inserir no Histórico
        // [ALTERADO] Adicionada a coluna cleaning_frequency
        $sqlHist = "INSERT INTO patient_location_history 
                    (patient_id, caregiver_id, hospital_name, sector, floor, bed, admission_date, latitude, longitude, cleaning_frequency)
                    VALUES (:pid, :cid, :hosp, :sec, :flr, :bed, :adm, :lat, :lng, :freq)";
        
        $stmtHist = $pdo->prepare($sqlHist);
        $stmtHist->execute([
            ':pid'  => $patientId,
            ':cid'  => $caregiverId,
            ':hosp' => $hospitalName,
            ':sec'  => $sector,
            ':flr'  => $floor,
            ':bed'  => $bed,
            ':adm'  => $admDate,
            ':lat'  => $lat,
            ':lng'  => $lng,
            ':freq' => $cleaningFreq // [NOVO] Bind da frequência
        ]);

        // 2. Commit da transação
        $pdo->commit();

        json(['success' => true, 'message' => 'Localização atualizada com sucesso!']);

    } catch (Exception $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log("Erro update-location: " . $e->getMessage());
        json(['success' => false, 'error' => $e->getMessage()]);
    }
}

/* api.php - Obter última localização (ATUALIZADO PARA PREENCHER FORMULÁRIO) */
 /* api.php - GET location (Simplificado) */
if ($action === 'get-last-location') {
    $patientId = $_GET['patientId'] ?? null;
    
    if (!$patientId) {
        json(['success' => false, 'message' => 'ID necessário']);
    }

    try {
        // ATUALIZADO: Adicionado 'id', 'cleaning_frequency', 'last_cleaning_date', 'last_checklist_data'
        $sql = "SELECT id, hospital_name, sector, floor, bed, admission_date, 
                       latitude, longitude, created_at,
                       cleaning_frequency, last_cleaning_date, last_checklist_data
                FROM patient_location_history 
                WHERE patient_id = :pid 
                ORDER BY created_at DESC 
                LIMIT 1";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':pid' => $patientId]);
        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            // Tratamento para admission_date
            if (empty($data['admission_date']) || strpos($data['admission_date'], '0000-00-00') !== false) {
                $data['admission_date'] = null;
            }

            // Tratamento para last_cleaning_date (Novo)
            if (empty($data['last_cleaning_date']) || strpos($data['last_cleaning_date'], '0000-00-00') !== false) {
                $data['last_cleaning_date'] = null;
            }

            json(['success' => true, 'data' => $data]);
        } else {
            json(['success' => false, 'message' => 'Sem histórico']);
        }

    } catch (Exception $e) {
        json(['success' => false, 'error' => $e->getMessage()]);
    }
}

if ($action === 'save-checklist') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!isset($input['location_id']) || !isset($input['checklist_data'])) {
        echo json_encode(['success' => false, 'message' => 'Dados incompletos.']);
        exit;
    }

    try {
        $sql = "UPDATE patient_location_history 
                SET last_cleaning_date = NOW(), 
                    last_checklist_data = :json_data 
                WHERE id = :loc_id";
        
        $stmt = $pdo->prepare($sql);
        $executed = $stmt->execute([
            ':json_data' => json_encode($input['checklist_data']), 
            ':loc_id'    => $input['location_id']
        ]);

        // --- A CORREÇÃO ESTÁ AQUI ---
        // Verificamos se o comando rodou E se alguma linha foi realmente alterada
        if ($executed && $stmt->rowCount() > 0) {
            echo json_encode(['success' => true, 'message' => 'Salvo com sucesso!']);
        } else {
            // Se chegou aqui, o ID não existe ou os dados já eram idênticos
            error_log("Tentativa de update falhou. ID: " . $input['location_id']);
            echo json_encode(['success' => false, 'message' => 'Nenhum registro encontrado para atualizar. Verifique o ID.']);
        }

    } catch (PDOException $e) {
        http_response_code(500);
        error_log("Erro SQL: " . $e->getMessage()); // Log no servidor é vital
        echo json_encode(['success' => false, 'error' => 'Erro ao salvar: ' . $e->getMessage()]);
    }
    exit;
}

/* --- INÍCIO DAS NOVAS FUNCIONALIDADES DO PAINEL DO PACIENTE --- */

// 1. Salvar Ação de Emergência
if ($action === 'log-emergency') {
    $pid = $input['patientId'] ?? null;
    $cid = $input['caregiverId'] ?? null;
    $type = $input['actionType'] ?? 'General';
    $lat = $input['lat'] ?? null;
    $lon = $input['lon'] ?? null;

    if (!$pid || !$cid) json(['success'=>false, 'message'=>'Dados incompletos.']);

    $stmt = $pdo->prepare("INSERT INTO emergency_logs (patient_id, caregiver_id, action_type, latitude, longitude, created_at) VALUES (:pid, :cid, :type, :lat, :lon, NOW())");
    $stmt->execute([':pid'=>$pid, ':cid'=>$cid, ':type'=>$type, ':lat'=>$lat, ':lon'=>$lon]);
    json(['success'=>true]);
}

// 2. História/Diário (Salvar e Ler)
if ($action === 'save-history') {
    $pid = $input['patientId'];
    $cid = $input['caregiverId'];
    $content = $input['content'];
    $isPublic = $input['isPublic'] ? 1 : 0;
    $lat = $input['lat'] ?? null;
    $lon = $input['lon'] ?? null;

    $stmt = $pdo->prepare("INSERT INTO history_posts (patient_id, caregiver_id, content, is_public, latitude, longitude, created_at) VALUES (:pid, :cid, :content, :public, :lat, :lon, NOW())");
    $stmt->execute([':pid'=>$pid, ':cid'=>$cid, ':content'=>$content, ':public'=>$isPublic, ':lat'=>$lat, ':lon'=>$lon]);
    json(['success'=>true]);
}

if ($action === 'get-history') {
    $pid = $_GET['patientId'];
    // Busca postagens públicas OU privadas apenas do próprio cuidador
    $stmt = $pdo->prepare("
        SELECT h.*, u.nickname as author_name 
        FROM history_posts h 
        LEFT JOIN users u ON h.caregiver_id = u.id
        WHERE h.patient_id = :pid 
        ORDER BY h.created_at DESC LIMIT 50");
    $stmt->execute([':pid'=>$pid]);
    json(['success'=>true, 'data'=>$stmt->fetchAll(PDO::FETCH_ASSOC)]);
}

// 3. Decisões em Equipe
if ($action === 'create-decision') {
    $pid = $input['patientId'];
    $cid = $input['caregiverId'];
    $title = $input['title'];
    $desc = $input['description'];
    
    // Verifica no banco se é premium
    $stmt = $pdo->prepare("SELECT is_premium FROM users WHERE id = ?");
    $stmt->execute([$cid]);
    $isPrem = $stmt->fetchColumn();

    if (!$isPrem) {
        // Retorna erro e o app não executa a ação
        json(['success'=>false, 'message'=>'Funcionalidade exclusiva Premium.']);
        exit;
    }
    
    // CORREÇÃO: Trata a data vinda do input datetime-local (remove o 'T')
    $rawDeadline = $input['deadline'] ?? null;
    $deadline = $rawDeadline ? str_replace('T', ' ', $rawDeadline) : null;
    
    $options = $input['options'] ?? [];

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("INSERT INTO decisions (patient_id, created_by_caregiver_id, title, description, deadline) VALUES (:pid, :cid, :title, :desc, :deadline)");
        $stmt->execute([':pid'=>$pid, ':cid'=>$cid, ':title'=>$title, ':desc'=>$desc, ':deadline'=>$deadline]);
        $decisionId = $pdo->lastInsertId();

        $stmtOpt = $pdo->prepare("INSERT INTO decision_options (decision_id, option_text) VALUES (:did, :txt)");
        foreach ($options as $opt) {
            if(trim($opt)) $stmtOpt->execute([':did'=>$decisionId, ':txt'=>$opt]);
        }
        $pdo->commit();
        json(['success'=>true]);
    } catch (Exception $e) {
        $pdo->rollBack();
        // Importante: Retorna o erro para o JS saber que falhou
        json(['success'=>false, 'message'=>$e->getMessage()]);
    }
}

if ($action === 'add-decision-option') {
    $did = $input['decisionId'] ?? null;
    $text = $input['optionText'] ?? null;
    $cid = $input['caregiverId'] ?? null;

    if (!$did || !$text) json(['success'=>false, 'message'=>'Dados incompletos.']);

    // 1. Verificar se a decisão existe e se o prazo ainda é válido
    $stmtCheck = $pdo->prepare("SELECT deadline FROM decisions WHERE id = :did");
    $stmtCheck->execute([':did'=>$did]);
    $decision = $stmtCheck->fetch(PDO::FETCH_ASSOC);

    if (!$decision) json(['success'=>false, 'message'=>'Decisão não encontrada.']);

    if ($decision['deadline']) {
        $deadline = new DateTime($decision['deadline']);
        $now = new DateTime();
        if ($now > $deadline) {
            json(['success'=>false, 'message'=>'Prazo encerrado. Não é possível adicionar opções.']);
            exit;
        }
    }

    // 2. Inserir a nova opção
    try {
        $stmt = $pdo->prepare("INSERT INTO decision_options (decision_id, option_text) VALUES (:did, :txt)");
        $stmt->execute([':did'=>$did, ':txt'=>$text]);
        
        // (Opcional) Poderíamos registrar quem adicionou, mas a tabela atual é simples.
        
        json(['success'=>true]);
    } catch (Exception $e) {
        json(['success'=>false, 'message'=>$e->getMessage()]);
    }
}

if ($action === 'get-decisions') {
    $pid = $_GET['patientId'];
    $stmt = $pdo->prepare("
        SELECT d.*, u.nickname as author 
        FROM decisions d 
        JOIN users u ON d.created_by_caregiver_id = u.id 
        WHERE d.patient_id = :pid 
        ORDER BY d.created_at DESC LIMIT 10");
    $stmt->execute([':pid'=>$pid]);
    $decisions = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($decisions as &$dec) {
        // NOVO: Busca contagem E os nomes concatenados de quem votou
        $stmtOpt = $pdo->prepare("
            SELECT 
                o.id, 
                o.option_text, 
                (SELECT COUNT(*) FROM decision_votes v WHERE v.option_id = o.id) as vote_count,
                (SELECT GROUP_CONCAT(u2.nickname SEPARATOR ', ') 
                 FROM decision_votes v2 
                 JOIN users u2 ON v2.caregiver_id = u2.id 
                 WHERE v2.option_id = o.id) as voters_names
            FROM decision_options o 
            WHERE o.decision_id = :did");
        $stmtOpt->execute([':did'=>$dec['id']]);
        $dec['options'] = $stmtOpt->fetchAll(PDO::FETCH_ASSOC);
        
        if (isset($_GET['userId'])) {
             $stmtVote = $pdo->prepare("SELECT option_id FROM decision_votes WHERE decision_id = :did AND caregiver_id = :cid");
             $stmtVote->execute([':did'=>$dec['id'], ':cid'=>$_GET['userId']]);
             $myVote = $stmtVote->fetch(PDO::FETCH_ASSOC);
             $dec['my_vote_option_id'] = $myVote ? $myVote['option_id'] : null;
        }
    }
    json(['success'=>true, 'data'=>$decisions]);
}

if ($action === 'vote-decision') {
    $did = $input['decisionId'];
    $oid = $input['optionId'];
    $cid = $input['caregiverId'];

    // Upsert voto (se já votou, muda o voto? ou bloqueia? Aqui vamos permitir mudar deletando o anterior)
    $pdo->beginTransaction();
    $pdo->exec("DELETE FROM decision_votes WHERE decision_id = $did AND caregiver_id = $cid");
    $stmt = $pdo->prepare("INSERT INTO decision_votes (decision_id, option_id, caregiver_id) VALUES (:did, :oid, :cid)");
    $stmt->execute([':did'=>$did, ':oid'=>$oid, ':cid'=>$cid]);
    $pdo->commit();
    json(['success'=>true]);
}

if ($action === 'delete-decision') {

    $decisionId = $input['decision_id'] ?? null;
    $userId     = $input['user_id'] ?? null;

    if (!$decisionId) {
        json(['success' => false, 'message' => 'decision_id não informado.']);
        exit;
    }

    try {
        $pdo->beginTransaction();

        // Verifica se a decisão existe
        $stmtCheck = $pdo->prepare("SELECT id FROM decisions WHERE id = :id");
        $stmtCheck->execute([':id' => $decisionId]);

        if ($stmtCheck->rowCount() === 0) {
            $pdo->rollBack();
            json(['success' => false, 'message' => 'Decisão não encontrada.']);
            exit;
        }

        // Deleta votos
        $pdo->prepare(
            "DELETE FROM decision_votes WHERE decision_id = :id"
        )->execute([':id' => $decisionId]);

        // Deleta opções
        $pdo->prepare(
            "DELETE FROM decision_options WHERE decision_id = :id"
        )->execute([':id' => $decisionId]);

        // Deleta decisão
        $pdo->prepare(
            "DELETE FROM decisions WHERE id = :id"
        )->execute([':id' => $decisionId]);

        $pdo->commit();

        json(['success' => true, 'message' => 'Votação excluída com sucesso.']);

    } catch (PDOException $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log("Erro delete-decision: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno ao excluir votação.']);
    }
}

// 4. Adicionar Membro (Busca simples por email para convite - Simulação)
if ($action === 'invite-member') {
    $email = trim($input['email'] ?? '');
    $patientId = $input['patientId'] ?? null;
    // Supondo que você tenha o ID de quem está convidando na sessão ou token (ex: $currentUserId)
    // Se não tiver, pode passar null ou enviar no input
    $invitedBy = $input['invitedBy'] ?? null; 

    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json(['success' => false, 'message' => 'E-mail inválido.']);
    }
    if (!$patientId) {
        json(['success' => false, 'message' => 'ID do paciente não informado.']);
    }

    try {
        // 1. Dados do Paciente
        $stmtP = $pdo->prepare("SELECT nickname FROM patients WHERE id = :pid LIMIT 1");
        $stmtP->execute([':pid' => $patientId]);
        $patient = $stmtP->fetch(PDO::FETCH_ASSOC);
        
        if (!$patient) {
            json(['success' => false, 'message' => 'Paciente não encontrado.']);
        }
        $nomePaciente = $patient['nickname'];

        // 2. Verifica se usuário já existe
        $stmt = $pdo->prepare("SELECT id, nickname FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // --- CENÁRIO A: USUÁRIO JÁ EXISTE ---
        if ($user) {
            $stmtLink = $pdo->prepare("INSERT IGNORE INTO patient_caregivers (patient_id, caregiver_id, nickname) VALUES (:pid, :cid, 'Convidado')");
            $stmtLink->execute([':pid' => $patientId, ':cid' => $user['id']]);

            if ($stmtLink->rowCount() > 0) {
                // Envia e-mail de aviso
                $titulo = "Acesso Concedido";
                $msg = "Olá, <b>{$user['nickname']}</b>.<br>Você foi adicionado à equipe de <b>$nomePaciente</b>.";
                $html = gerarTemplateEmail($titulo, $msg, "Acessar", $URL_APP);
                enviarEmailSistema($email, $user['nickname'], "Novo Paciente: $nomePaciente", $html);

                json(['success' => true, 'message' => 'Usuário adicionado à equipe!']);
            } else {
                json(['success' => true, 'message' => 'Usuário já faz parte da equipe.']);
            }
        } 
        // --- CENÁRIO B: USUÁRIO NÃO EXISTE (GRAVAR CONVITE PENDENTE) ---
        else {
            // Insere na tabela de pendentes (INSERT IGNORE evita erro se já convidou antes)
            $stmtPend = $pdo->prepare("
                INSERT IGNORE INTO pending_invites (email, patient_id, invited_by_user_id, created_at) 
                VALUES (:email, :pid, :by, NOW())
            ");
            $stmtPend->execute([
                ':email' => $email,
                ':pid' => $patientId,
                ':by' => $invitedBy
            ]);

            // Envia o e-mail de convite para cadastro
            $titulo = "Convite para Equipe de Cuidado";
            $msg = "Olá.<br><br>" .
                   "Você foi convidado para ajudar a cuidar de <b>$nomePaciente</b>.<br>" .
                   "Para aceitar o convite e acessar os dados, crie sua conta gratuitamente clicando abaixo.<br>" .
                   "<i>O acesso ao paciente será liberado automaticamente após o cadastro.</i>";
            
            $linkCadastro = $URL_APP;
            $linkCadastro .= "cadastro.html?email=" . urlencode($email); // Dica: preencha o email no form automaticamente
            $html = gerarTemplateEmail($titulo, $msg, "Criar Conta e Aceitar", $linkCadastro);
            
            enviarEmailSistema($email, 'Convidado', "Convite: Cuidar de $nomePaciente", $html);

            json(['success' => true, 'message' => 'Convite enviado! O acesso será liberado assim que o usuário se cadastrar.']);
        }

    } catch (PDOException $e) {
        json(['success' => false, 'error' => 'Erro: ' . $e->getMessage()]);
    }
}

// 5. Atualizar Situação da Doença e Encerramento
if ($action === 'update-disease-journey') {
    $pid = $input['patientId'];
    $cid = $input['caregiverId'];
    $type = $input['updateType']; // 'disease_update' ou 'journey_end'
    $details = $input['details']; // JSON string ou texto
    $lat = $input['lat'] ?? null;
    $lon = $input['lon'] ?? null;

    if ($type === 'disease_update') {
        $illness = $input['illness'];
        $subtype = $input['subtype'];
        $stmt = $pdo->prepare("UPDATE patients SET illness = :ill, illness_subtype = :sub WHERE id = :pid");
        $stmt->execute([':ill'=>$illness, ':sub'=>$subtype, ':pid'=>$pid]);
    } elseif ($type === 'journey_end') {
        $stmt = $pdo->prepare("UPDATE patients SET journey_status = 'ended' WHERE id = :pid");
        $stmt->execute([':pid'=>$pid]);
    }

    // Registrar na evolução
    $stmtHist = $pdo->prepare("INSERT INTO patient_evolution (patient_id, caregiver_id, event_type, details, latitude, longitude) VALUES (:pid, :cid, :evt, :det, :lat, :lon)");
    $stmtHist->execute([':pid'=>$pid, ':cid'=>$cid, ':evt'=>$type, ':det'=>$details, ':lat'=>$lat, ':lon'=>$lon]);
    
    json(['success'=>true]);
}

// Adicione no api.php
if ($action === 'get-patient-details') {
    $pid = $_GET['patientId'] ?? null;
    if ($pid) {
        $stmt = $pdo->prepare("SELECT id, nickname, illness, illness_subtype,created_at FROM patients WHERE id = :pid");
        $stmt->execute([':pid' => $pid]);
        $patient = $stmt->fetch(PDO::FETCH_ASSOC);
        json(['success' => true, 'patient' => $patient]);
    } else {
        json(['success' => false, 'message' => 'ID ausente']);
    }
}

// --- Buscar Histórico de Emergência (Pronto Atendimento) ---
if ($action === 'get-emergency-logs') {
    $pid = $_GET['patientId'] ?? null;
    
    // Busca os últimos 20 registros, trazendo o nome do cuidador (nickname)
    $stmt = $pdo->prepare("
        SELECT e.*, u.nickname as caregiver_name 
        FROM emergency_logs e 
        LEFT JOIN users u ON e.caregiver_id = u.id 
        WHERE e.patient_id = :pid 
        ORDER BY e.created_at DESC 
        LIMIT 20
    ");
    $stmt->execute([':pid' => $pid]);
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    json(['success' => true, 'data' => $logs]);
}

// ==========================================
// CONTRATATAR PLANO PREMIUM
// ==========================================

if ($action === 'start-premium-trial') {
    $uid = $input['userId'] ?? null;
    $plan = $input['plan'] ?? 'monthly';
    $method = $input['method'] ?? 'card';
    
    if (!$uid) json(['success'=>false, 'message'=>'User ID necessário.']);

    // Calcula datas
    $now = date('Y-m-d H:i:s');
    $trialDays = ($method === 'pix') ? 19 : 14; // Bônus para Pix
    $trialEnd = date('Y-m-d H:i:s', strtotime("+$trialDays days"));
    $billingDate = $trialEnd; 
    
    try {
        // CORREÇÃO: Usar INSERT ... ON DUPLICATE KEY UPDATE
        // Isso previne erro se o usuário já tiver clicado antes, apenas atualizando as datas.
        $sql = "INSERT INTO subscriptions (user_id, plan_type, status, trial_start_date, trial_end_date, next_billing_date, payment_method, auto_renew) 
                VALUES (:uid, :plan, 'trial', :now, :trial_end, :billing, :method, 1)
                ON DUPLICATE KEY UPDATE 
                    plan_type = VALUES(plan_type),
                    status = 'trial',
                    trial_start_date = VALUES(trial_start_date),
                    trial_end_date = VALUES(trial_end_date),
                    next_billing_date = VALUES(next_billing_date),
                    payment_method = VALUES(payment_method),
                    auto_renew = 1";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':uid'=>$uid, 
            ':plan'=>$plan, 
            ':now'=>$now, 
            ':trial_end'=>$trialEnd, 
            ':billing'=>$billingDate, 
            ':method'=>$method
        ]);
        
        // Garante que a flag no usuário seja atualizada
        $pdo->prepare("UPDATE users SET is_premium = 1 WHERE id = ?")->execute([$uid]);
        
        json(['success'=>true, 'message'=>'Trial iniciado com sucesso!', 'trial_end'=>$trialEnd]);

    } catch (Exception $e) {
        json(['success'=>false, 'message'=>'Erro ao processar assinatura: ' . $e->getMessage()]);
    }
}

// 2. Verificar Status e Streak
if ($action === 'get-premium-status') {
    $uid = $_GET['userId'] ?? null;

    if (!$uid) {
        json(['success' => false, 'message' => 'User ID não fornecido']);
        exit;
    }

    // Consulta otimizada na tabela que você já possui
    $stmt = $pdo->prepare("SELECT plan_type, status, trial_end_date, streak_days FROM subscriptions WHERE user_id = :uid LIMIT 1");
    $stmt->execute([':uid' => $uid]);
    $sub = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Estrutura padrão de resposta
    $response = [
        'success' => true,
        'is_premium' => false,
        'trial_used' => false, // Campo fundamental para o modal se adaptar
        'streak' => 0,
        'plan_status' => 'free',
        'data' => null
    ];

    if (!$sub) {
        // Se NÃO tem registro em subscriptions, nunca usou trial
        // Mantém trial_used = false
    } else {
        // Se TEM registro, já iniciou o trial em algum momento
        $response['trial_used'] = true; 
        $response['streak'] = $sub['streak_days'] ?? 0;
        $response['plan_status'] = $sub['status'];
        $response['data'] = $sub;

        // Verifica se o status é considerado Premium
        $isActive = ($sub['status'] === 'active' || $sub['status'] === 'trial');

        // Validação extra de data (segurança caso o status no banco não tenha atualizado via cron job)
        if ($isActive && !empty($sub['trial_end_date'])) {
            try {
                $hoje = new DateTime();
                $validade = new DateTime($sub['trial_end_date']);
                
                // Se era trial e a data passou, revoga o acesso premium
                if ($sub['status'] === 'trial' && $validade < $hoje) {
                    $isActive = false;
                    // trial_used continua true, pois já gastou o período
                }
            } catch (Exception $e) {
                // Erro na data, mantém o status do banco por segurança
            }
        }

        $response['is_premium'] = $isActive;
    }

    // Lógica de Gamificação (mantida do seu original)
    // Aqui você pode adicionar lógica para incrementar streak se for o primeiro acesso do dia
    
    json($response);
}

// 3. Winback (A tentativa de cancelamento)
if ($action === 'attempt-cancel') {
    $uid = $input['userId'];
    // Aqui não cancelamos direto. Retornamos uma oferta ou mensagem emocional.
    json(['success'=>true, 'strategy'=>'bell_winback', 'message'=>'Não silencie o sino agora.']);
}

// canela o plano Premium
if ($action === 'plan-cancel') {
    $data = json_decode(file_get_contents('php://input'), true);
    $userId = $data['userId'] ?? null;

    if (!$userId) {
        json(['success' => false, 'message' => 'Usuário não identificado.']);
    }

    try {
        // 1. Buscar dados do usuário (ID da assinatura e Token se necessário)
        $stmt = $pdo->prepare("SELECT subscription_id FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // 2. Se tiver um ID de assinatura do Mercado Pago, tenta cancelar lá
        if (!empty($user['subscription_id'])) {
            $mpAccessToken = MP_ACCESS_TOKEN; // Coloque seu token de produção aqui
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://api.mercadopago.com/preapproval/" . $user['subscription_id']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT"); // Mercado Pago usa PUT para atualizar status
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(["status" => "cancelled"]));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Content-Type: application/json",
                "Authorization: Bearer " . $mpAccessToken
            ]);
            
            $response = curl_exec($ch);
            curl_close($ch);
            // Opcional: Logar a resposta do MP para debug
            // error_log("MP Cancel Response: " . $response);
        }

        // 3. Atualizar o banco de dados local para remover o Premium
        $update = $pdo->prepare("UPDATE users SET is_premium = 0, subscription_id = NULL WHERE id = :id");
        $update->execute([':id' => $userId]);
        
        //deleta o registro na subscriptions
        $update = $pdo->prepare("UPDATE subscriptions SET status = 'canceled' WHERE user_id = :id");
        $update->execute([':id' => $userId]);

        json(['success' => true, 'message' => 'Plano cancelado com sucesso.']);

    } catch (PDOException $e) {
        error_log("Erro ao cancelar plano: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno ao cancelar plano.']);
    }
}

if ($action === 'get-price-preview') {
    // 1. Seu preço FIXO em Reais
    $precoFixoReais = 150.00; // Exemplo: O plano custa 150 reais

    // 2. Busca cotação (USD-BRL)
    $url = 'https://economia.awesomeapi.com.br/last/USD-BRL';
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $resposta = json_decode(curl_exec($curl), true);
    curl_close($curl);

    // Pega a cotação de VENDA (bid) ou ALTA (high)
    // Se o dólar está R$ 5,00
    $cotacao = isset($resposta['USDBRL']['high']) ? floatval($resposta['USDBRL']['high']) : 5.00;

    // 3. Converte para exibir (DIVIDIR pelo dólar)
    // R$ 150 / 5 = $ 30
    $precoEstimadoUSD = $precoFixoReais / $cotacao;

    json([
        'success' => true,
        'brl_real_price' => $precoFixoReais, // O valor que será cobrado de verdade
        'usd_display_price' => round($precoEstimadoUSD, 2), // O valor para mostrar na tela
        'rate_used' => $cotacao
    ]);
    exit;
}

if ($action === 'create-pix-payment') {
    // 1. Recebe e decodifica os dados enviados pelo Javascript
    $input = json_decode(file_get_contents('php://input'), true);
    
    $userId = $input['userId'] ?? null;
    $email = $input['email'] ?? 'email_do_usuario@exemplo.com'; 
    $description = $input['description'] ?? 'Assinatura Premium - Acura Sistema';
    
    // Pega o valor enviado pelo JS, se não vier, usa 17.90 como fallback seguro
    $amount = $input['transaction_amount'] ?? ($input['amount'] ?? 17.90);

    if (!$userId) {
        json(['success' => false, 'message' => 'Usuário não identificado.']);
        exit;
    }

    // 2. Configura a chamada ao Mercado Pago
    $accessToken = MP_ACCESS_TOKEN; // Certifique-se que esta constante está definida no topo do arquivo
    
    $paymentData = [
        "transaction_amount" => (float)$amount, // Garante que seja número (float)
        "description" => $description,
        "payment_method_id" => "pix",
        "payer" => [
            "email" => $email,
            "first_name" => "Usuario",
            "last_name" => "ID: " . $userId
        ]
    ];

    // 3. Executa o CURL (Requisição direta à API)
    $ch = curl_init('https://api.mercadopago.com/v1/payments');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($paymentData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $accessToken,
        'X-Idempotency-Key: ' . uniqid('pix_', true) // Chave única para evitar pagamentos duplicados
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $json = json_decode($response, true);

    // 4. Verifica se deu certo (Status 201 = Criado)
    if ($httpCode === 201 && isset($json['id'])) {
        
        // Extrai os dados com segurança usando o operador null coalescing (??)
        $paymentId = $json['id'];
        $qrCode = $json['point_of_interaction']['transaction_data']['qr_code'] ?? '';
        $qrCodeBase64 = $json['point_of_interaction']['transaction_data']['qr_code_base64'] ?? '';

        // 5. SALVA NO BANCO DE DADOS (Passo Crucial)
        try {
            // Verifique se sua tabela se chama 'subscriptions' ou 'assinaturas'
            $stmt = $pdo->prepare("INSERT INTO subscriptions (user_id, status, subscription_id, type, amount, created_at) VALUES (:uid, 'pending', :subId, 'pix', :amount, NOW())");
            
            $stmt->execute([
                ':uid' => $userId,
                ':subId' => $paymentId,
                ':amount' => $amount
            ]);

        } catch (PDOException $e) {
            // Se der erro no banco, loga no servidor, mas não trava o retorno do Pix para o usuário
            error_log("Erro ao salvar Pix no banco: " . $e->getMessage());
        }

        // 6. Retorna para o Front-end
        json([
            'success' => true, 
            'payment_id' => $paymentId,
            'qr_code' => $qrCode, 
            'qr_code_base64' => $qrCodeBase64 // Importante manter este nome para o JS funcionar
        ]);

    } else {
        // Loga o erro para você depurar se precisar
        $erroMsg = $json['message'] ?? 'Erro desconhecido na API do Mercado Pago';
        error_log("Falha MP PIX: " . json_encode($json));
        
        json(['success' => false, 'message' => 'Erro ao gerar Pix: ' . $erroMsg]);
    }
}

if ($action === 'create-card-payment') {
    error_log("🔵 [CARD PAYMENT] Iniciando processamento...");
    
    try {
        // 🔍 BUSCA INTELIGENTE DO AUTOLOAD
        $possiblePaths = [
            __DIR__ . '/mercadopago/vendor/autoload.php',     // Caminho padrão
            __DIR__ . '/vendor/autoload.php',                 // Raiz do projeto
            __DIR__ . '/../vendor/autoload.php',              // Um nível acima
            '/home/u610916991/domains/acura.vc/public_html/mercadopago/vendor/autoload.php', // Caminho absoluto Hostinger
            '/home/u610916991/public_html/mercadopago/vendor/autoload.php' // Alternativo Hostinger
        ];
        
        $autoloadPath = null;
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                $autoloadPath = $path;
                error_log("✅ [CARD PAYMENT] Autoload encontrado em: $path");
                break;
            } else {
                error_log("⚠️ [CARD PAYMENT] Não encontrado em: $path");
            }
        }
        
        if (!$autoloadPath) {
            error_log("❌ [CARD PAYMENT] ERRO: Autoload não encontrado em nenhum caminho testado");
            error_log("📍 [CARD PAYMENT] Diretório atual: " . __DIR__);
            error_log("📂 [CARD PAYMENT] Conteúdo do diretório:");
            error_log(print_r(scandir(__DIR__), true));
            
            json([
                'success' => false, 
                'message' => 'SDK MercadoPago não instalado.',
                'debug' => [
                    'current_dir' => __DIR__,
                    'tested_paths' => $possiblePaths,
                    'suggestion' => 'Execute: composer require mercadopago/dx-php'
                ]
            ]);
            exit;
        }
        
        require_once $autoloadPath;
        error_log("✅ [CARD PAYMENT] SDK carregado com sucesso");
        
        // VALIDAR TOKEN DE ACESSO
        if (!defined('MP_ACCESS_TOKEN') || empty(MP_ACCESS_TOKEN)) {
            error_log("❌ [CARD PAYMENT] MP_ACCESS_TOKEN não configurado");
            json(['success' => false, 'message' => 'Token MercadoPago não configurado.']);
            exit;
        }
        
        MercadoPago\SDK::setAccessToken(MP_ACCESS_TOKEN);
        error_log("✅ [CARD PAYMENT] Token configurado");
        
        // VALIDAR DADOS DE ENTRADA
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!is_array($input)) {
            error_log("❌ [CARD PAYMENT] JSON de entrada inválido");
            json(['success' => false, 'message' => 'Dados de pagamento inválidos.']);
            exit;
        }
        
        $token           = $input['token'] ?? null;
        $paymentMethod   = $input['payment_method_id'] ?? null;
        $installments    = max(1, (int)($input['installments'] ?? 1));
        $email           = $input['email'] ?? null;
        $userId          = (int)($input['userId'] ?? 0);
        
        error_log("📦 [CARD PAYMENT] Dados recebidos - UserID: $userId, Email: $email, Method: $paymentMethod");
        
        if (!$token || !$paymentMethod || !$email || !$userId) {
            error_log("❌ [CARD PAYMENT] Campos obrigatórios ausentes");
            json(['success' => false, 'message' => 'Dados obrigatórios ausentes (token, email, método).']);
            exit;
        }
        
        // CRIAR PAGAMENTO NO MERCADOPAGO
        error_log("💳 [CARD PAYMENT] Criando pagamento...");
        
        $payment = new MercadoPago\Payment();
        
        $payment->transaction_amount = 29.90;
        $payment->token              = $token;
        $payment->description        = 'Plano Premium Acura';
        $payment->installments       = $installments;
        $payment->payment_method_id  = $paymentMethod;
        $payment->payer              = ['email' => $email];
        $payment->external_reference = 'user_' . $userId;
        
        // ✅ NOVO: Tenta salvar e captura o resultado
        $saveResult = $payment->save();
        
        // ✅ LOG DETALHADO DO RESULTADO
        error_log("📊 [CARD PAYMENT] Resultado do save(): " . ($saveResult ? 'true' : 'false'));
        error_log("📊 [CARD PAYMENT] Payment ID: " . ($payment->id ?? 'NULL'));
        error_log("📊 [CARD PAYMENT] Status: " . ($payment->status ?? 'NULL'));
        error_log("📊 [CARD PAYMENT] Status Detail: " . ($payment->status_detail ?? 'NULL'));
        
        // ✅ NOVO: Verificar erros da API
        if (isset($payment->error)) {
            error_log("❌ [CARD PAYMENT] Erro da API MP: " . json_encode($payment->error));
        }
        
        // ✅ NOVO: Log do objeto completo (apenas em desenvolvimento)
        error_log("🔍 [CARD PAYMENT] Objeto Payment completo: " . json_encode($payment));
        
        $paymentStatus = $payment->status ?? 'unknown';
        $paymentId = $payment->id ?? 'N/A';
        
        // ✅ NOVO: Validação rigorosa
        if (!$saveResult || !$payment->id) {
            error_log("❌ [CARD PAYMENT] FALHA: Pagamento não foi salvo no MercadoPago");
            
            $errorMsg = 'Falha ao processar pagamento';
            $errorDetail = 'Token inválido ou expirado';
            
            // Tenta extrair erro específico
            if (isset($payment->error)) {
                $errorMsg = $payment->error->message ?? $errorMsg;
                $errorDetail = json_encode($payment->error);
            }
            
            json([
                'success' => false,
                'message' => $errorMsg,
                'detail' => $errorDetail,
                'debug' => [
                    'save_result' => $saveResult,
                    'payment_id' => $payment->id ?? null,
                    'status' => $payment->status ?? null,
                    'status_detail' => $payment->status_detail ?? null
                ]
            ]);
            exit;
        }
        
        error_log("📊 [CARD PAYMENT] Status do pagamento: $paymentStatus (ID: $paymentId)");
        
        // ATUALIZAR BANCO SE APROVADO
        if ($paymentStatus === 'approved') {
            error_log("✅ [CARD PAYMENT] Pagamento APROVADO - Ativando Premium...");
            
            // ✅ CORREÇÃO: Atualiza apenas is_premium (coluna existente)
            $stmt = $pdo->prepare("
                UPDATE users
                SET is_premium = 1
                WHERE id = :uid
            ");
            $stmt->execute([':uid' => $userId]);
            
            // ✅ NOVO: Atualiza/cria registro na tabela subscriptions
            $now = date('Y-m-d H:i:s');
            $endDate = date('Y-m-d H:i:s', strtotime('+30 days')); // 30 dias de Premium
            
            $stmtSub = $pdo->prepare("
                INSERT INTO subscriptions 
                (user_id, plan_type, status, trial_start_date, trial_end_date, next_billing_date, payment_method, auto_renew)
                VALUES (:uid, 'monthly', 'active', :now, :end, :end, 'card', 1)
                ON DUPLICATE KEY UPDATE 
                    status = 'active',
                    trial_end_date = :end,
                    next_billing_date = :end
            ");
            
            $stmtSub->execute([
                ':uid' => $userId,
                ':now' => $now,
                ':end' => $endDate
            ]);
            
            error_log("✅ [CARD PAYMENT] Usuário $userId atualizado no banco (Premium ativo até $endDate)");
        } else {
            error_log("⚠️ [CARD PAYMENT] Status não aprovado: $paymentStatus");
        }
        
        // RETORNAR RESPOSTA JSON
        json([
            'success'       => true,
            'status'        => $paymentStatus,
            'status_detail' => $payment->status_detail ?? 'N/A',
            'payment_id'    => $paymentId
        ]);
        
    } catch (MercadoPago\Exceptions\MPApiException $e) {
        $apiError = $e->getApiResponse();
        $errorMsg = $apiError['message'] ?? $e->getMessage();
        
        error_log("❌ [CARD PAYMENT] Erro API MercadoPago: $errorMsg");
        
        json([
            'success' => false,
            'message' => 'Erro ao processar pagamento',
            'detail'  => $errorMsg
        ]);
        
    } catch (Throwable $e) {
        error_log("❌ [CARD PAYMENT] ERRO FATAL: " . $e->getMessage());
        error_log("📍 [CARD PAYMENT] Linha: " . $e->getLine());
        
        json([
            'success' => false,
            'message' => 'Erro interno do servidor',
            'detail'  => $e->getMessage()
        ]);
    }
    
    exit;
}

if ($action === 'check-payment-status') {
    $paymentId = $input['paymentId'] ?? null;
    $uid = $input['userId'] ?? null;
    
    if (!$paymentId || !$uid) {
        json(['success' => false, 'status' => 'error', 'message' => 'Dados incompletos']);
    }

    // SEU TOKEN DO MERCADO PAGO
    $accessToken = MP_ACCESS_TOKEN; 

    // 1. Consulta a API do Mercado Pago
    $ch = curl_init("https://api.mercadopago.com/v1/payments/$paymentId");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json'
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $mpData = json_decode($response, true);
    
    // 2. Verifica o status
    if ($httpCode === 200 && isset($mpData['status'])) {
        $status = $mpData['status']; // approved, pending, rejected...
        
        if ($status === 'approved') {
            // 3. PAGAMENTO APROVADO: Ativar Assinatura no Banco AGORA
            // Reutilize a lógica de ativar trial/assinatura, mas agora como 'active'
            
            // Exemplo simplificado (idealmente use uma função reutilizável):
            $now = date('Y-m-d H:i:s');
            // 30 dias de acesso (exemplo mensal)
            $endDate = date('Y-m-d H:i:s', strtotime('+30 days')); 
            
            // Atualiza status para ACTIVE
            $stmt = $pdo->prepare("UPDATE subscriptions SET status = 'active', next_billing_date = :end WHERE user_id = :uid");
            $stmt->execute([':end' => $endDate, ':uid' => $uid]);
            
            // Atualiza User
            $pdo->prepare("UPDATE users SET is_premium = 1 WHERE id = :uid")->execute([':uid' => $uid]);
            
            json(['success' => true, 'status' => 'approved']);
        } else {
            json(['success' => true, 'status' => $status]); // pending, in_process
        }
    } else {
        json(['success' => false, 'status' => 'error', 'message' => 'Erro ao consultar MP']);
    }
}

if ($action === 'delete-account') {
    $uid = $input['userId'] ?? null;
    
    if (!$uid) {
        json(['success' => false, 'message' => 'ID de usuário necessário.']);
    }

    try {
        // Deletar o usuário
        // OBS: Como as tabelas 'patients', 'decisions', 'subscriptions', etc.
        // devem ter FOREIGN KEY ... ON DELETE CASCADE, isso apaga tudo.
        $stmt = $pdo->prepare("DELETE FROM subscriptions WHERE user_id = :uid");
        $stmt->execute([':uid' => $uid]);
        
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = :uid");
        $stmt->execute([':uid' => $uid]);
        
        if ($stmt->rowCount() > 0) {
            json(['success' => true, 'message' => 'Conta e dados excluídos permanentemente.']);
        } else {
            json(['success' => false, 'message' => 'Usuário não encontrado ou já excluído.']);
        }

    } catch (PDOException $e) {
        // Log do erro real no servidor
        error_log("Erro ao deletar conta: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno ao processar exclusão.']);
    }
}

// ==========================================
// AÇÃO: ABANDONAR PACIENTE (Desvincular)
// ==========================================
if ($action === 'abandon-patient') {
    $caregiverId = $_SESSION['user_id'] ?? null; 

    // Pega do input se não vier da sessão (Agora o JS está mandando!)
    if (!$caregiverId && isset($input['caregiver_id'])) {
        $caregiverId = $input['caregiver_id'];
    }

    $patientId = $input['patient_id'] ?? null;

    if (!$caregiverId || !$patientId) {
        json(['success' => false, 'message' => 'IDs de cuidador ou paciente inválidos.']);
        exit;
    }

    try {
        // TENTATIVA 1: Tabela de Relacionamento (Se existir tabela intermediária)
        // Verifique o nome real da sua tabela: 'caregiver_patient', 'pacientes_cuidadores', etc.
        $stmt = $pdo->prepare("DELETE FROM patient_caregivers WHERE caregiver_id = :cid AND patient_id = :pid");
        $stmt->execute([':cid' => $caregiverId, ':pid' => $patientId]);
        
        $deletados = $stmt->rowCount(); 
        json(['success' => true, 'message' => 'Vínculo removido com sucesso.']);
        

    } catch (Exception $e) {
        // Erro comum: Table doesn't exist. Isso ajuda a debugar.
        json(['success' => false, 'message' => 'Erro no banco de dados: ' . $e->getMessage()]);
    }
}

// 1. SOLICITAR O RESET (Envia o E-mail)
if ($action === 'request-password-reset') {
    $email = trim($input['email'] ?? '');
    
    // 1. Detecta o idioma enviado pelo front-end (Header: X-Lang)
    $headers = getallheaders();
    $lang = $headers['X-Lang'] ?? 'pt'; // Padrão pt se não enviado
    
    // Dicionário simples para o E-MAIL (Back-end)
    $emailTexts = [
        'pt' => [
            'subject' => 'Redefinição de Senha',
            'guest_subject' => 'Seu Convite para o Acura',
            'greeting' => 'Olá',
            'intro' => 'Recebemos uma solicitação para redefinir a senha da sua conta no Acura Vencer Cuidando.',
            'action' => 'Se foi você, clique no botão abaixo. Este link expira em 1 hora.',
            'btn_label' => 'Redefinir Minha Senha'
        ],
        'en' => [
            'subject' => 'Password Reset',
            'guest_subject' => 'Your Acura Invitation',
            'greeting' => 'Hello',
            'intro' => 'We received a request to reset your password for your Acura Vencer Cuidando account.',
            'action' => 'If this was you, click the button below. This link expires in 1 hour.',
            'btn_label' => 'Reset My Password'
        ],
        'es' => [
            'subject' => 'Restablecimiento de Contraseña',
            'guest_subject' => 'Su Invitación a Acura',
            'greeting' => 'Hola',
            'intro' => 'Recibimos una solicitud para restablecer la contraseña de su cuenta Acura Vencer Cuidando.',
            'action' => 'Si fue usted, haga clic en el botón de abajo. Este enlace caduca en 1 hora.',
            'btn_label' => 'Restablecer Mi Contraseña'
        ]
    ];
    
    // Garante fallback para inglês se vier um idioma desconhecido
    $txt = $emailTexts[$lang] ?? $emailTexts['en'];

    // 2. Validação básica
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        json(['success' => false, 'code' => 'INVALID_EMAIL_FORMAT', 'message' => 'Formato de e-mail inválido.']);
    }

    // --- NOTA DO DANIEL: VERIFICAÇÃO DE CONVIDADOS ---
    // Verifica se é um convidado (tabela guests)
    $stmtGuest = $pdo->prepare("SELECT id, name, invite_code FROM guests WHERE email = :email LIMIT 1");
    $stmtGuest->execute([':email' => $email]);
    $guest = $stmtGuest->fetch(PDO::FETCH_ASSOC);

    if ($guest) {
        // Se for convidado, reenviamos o código de convite original
        $inviteLink = "https://" . $_SERVER['HTTP_HOST'] . "/convite.html?code=" . $guest['invite_code'];
        
        $msgGuest = $txt['greeting'] . ", <b>" . htmlspecialchars($guest['name']) . "</b>.<br><br>" .
                    "Detectamos que você tentou recuperar a senha, mas sua conta ainda é de convidado.<br>" .
                    "Use o link abaixo para acessar:";
        
        $htmlGuest = gerarTemplateEmail($txt['guest_subject'], $msgGuest, "Acessar Convite", $inviteLink);
        enviarEmailSistema($email, $guest['name'], $txt['guest_subject'], $htmlGuest);

        // Retorna sucesso genérico para evitar enumeração
        json([
            'success' => true, 
            'code' => 'RESET_LINK_SENT', // Código para o Front traduzir
            'message' => 'Se o e-mail estiver cadastrado, você receberá as instruções.'
        ]);
        exit;
    }

    // --- FLUXO NORMAL: USUÁRIOS REGISTRADOS ---
    $stmt = $pdo->prepare("SELECT id, nickname FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // --- SEGURANÇA: PROTEÇÃO CONTRA ENUMERAÇÃO ---
    if (!$user) {
        sleep(rand(1, 2)); // Delay de segurança
        json([
            'success' => true, 
            'code' => 'RESET_LINK_SENT', // O mesmo código de sucesso
            'message' => 'Se o e-mail estiver cadastrado, você receberá as instruções.'
        ]);
        exit;
    }

    // --- GERAÇÃO DO TOKEN ---
    $tokenRaw = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $tokenRaw);
    $expires = date('Y-m-d H:i:s', strtotime('+1 hour'));

    try {
        // Atualiza o banco
        $update = $pdo->prepare("UPDATE users SET reset_token_hash = :hash, reset_expires_at = :exp WHERE id = :uid");
        $update->execute([
            ':hash' => $tokenHash, 
            ':exp' => $expires, 
            ':uid' => $user['id']
        ]);

        // --- ENVIO DO E-MAIL (COM IDIOMA CORRETO) ---
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
        $host = $_SERVER['HTTP_HOST'];
        $linkReset = "$protocol://$host/nova-senha.html?token=" . $tokenRaw;

        $nome = $user['nickname'] ?? 'Usuário';
        
        // Monta mensagem traduzida
        $msgUser = $txt['greeting'] . ", <b>" . htmlspecialchars($nome) . "</b>.<br><br>" .
                   $txt['intro'] . "<br>" .
                   $txt['action'];

        $html = gerarTemplateEmail($txt['subject'], $msgUser, $txt['btn_label'], $linkReset);

        enviarEmailSistema($email, $nome, $txt['subject'], $html);

        json([
            'success' => true, 
            'code' => 'RESET_LINK_SENT', // Código para o Front traduzir
            'message' => 'Se o e-mail estiver cadastrado, você receberá as instruções.'
        ]);

    } catch (PDOException $e) {
        error_log("Erro reset senha: " . $e->getMessage());
        json([
            'success' => false, 
            'code' => 'SERVER_ERROR',
            'message' => 'Erro no servidor.'
        ]);
    }
}

// 2. EFETIVAR A TROCA (Recebe Token + Nova Senha)
if ($action === 'reset-password-confirm') {
    $token = $input['token'] ?? '';
    $newPassword = $input['new_password'] ?? '';

    if (!$token || !$newPassword) {
        json(['success' => false, 'message' => 'Dados incompletos.']);
    }

    // 1. Recriar o hash do token recebido para comparar com o banco
    $tokenHash = hash('sha256', $token);

    // 2. Buscar usuário com este hash E que o token ainda não expirou
    $stmt = $pdo->prepare("
        SELECT id FROM users 
        WHERE reset_token_hash = :hash 
        AND reset_expires_at > NOW()
    ");
    $stmt->execute([':hash' => $tokenHash]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        json(['success' => false, 'message' => 'Link inválido ou expirado. Solicite uma nova redefinição.']);
    }

    // 3. Atualizar a senha e limpar o token (para não ser usado 2 vezes)
    $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
    
    $update = $pdo->prepare("
        UPDATE users 
        SET password_hash = :p, reset_token_hash = NULL, reset_expires_at = NULL 
        WHERE id = :uid
    ");
    
    if ($update->execute([':p' => $newHash, ':uid' => $user['id']])) {
        
        // Opcional: Enviar e-mail avisando que a senha foi alterada
        // enviarEmailSistema(... "Sua senha foi alterada" ...);
        
        json(['success' => true, 'message' => 'Senha alterada com sucesso! Faça login.']);
    } else {
        json(['success' => false, 'message' => 'Erro ao atualizar senha.']);
    }
}

// ==========================================
// MÓDULO FINANCEIRO (OncoFinanças Integrado)
// ==========================================

// 1. Carregar dados iniciais (Categorias e Dicas)
if ($action === 'finance-get-initial-data') {
    try {
        // Buscar categorias
        $stmt = $pdo->query("SELECT * FROM finance_categories ORDER BY prioridade ASC");
        $categorias = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Buscar dicas
        $stmt = $pdo->query("SELECT * FROM finance_tips ORDER BY relevancia DESC");
        $dicas = $stmt->fetchAll(PDO::FETCH_ASSOC);

        json(['success' => true, 'categorias' => $categorias, 'dicas' => $dicas]);
    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao buscar dados financeiros: ' . $e->getMessage()]);
    }
}

// 2. Adicionar Despesa
// 3. Adicionar Despesa (ATUALIZADO COM DETALHES DE MEDICAMENTOS)
if ($action === 'finance-add-expense') {
    $patientId   = $input['patient_id'] ?? null;
    $caregiverId = $_SESSION['user_id'] ?? $input['caregiver_id'] ?? null;
    $categoriaId = $input['categoria_id'] ?? null;
    $descricao   = $input['descricao'] ?? '';
    $valor       = $input['valor'] ?? 0;
    $dataDespesa = $input['data_despesa'] ?? date('Y-m-d');
    $recorrente  = $input['recorrente'] ?? 0;
    
    $originType  = $input['origin_type'] ?? null;
    $originId    = $input['origin_id'] ?? null;

    // Novos campos de Medicamentos
    $medTipo     = $input['med_tipo'] ?? null;
    $medConteudo = $input['med_conteudo'] ?? null;
    $medUnidade  = $input['med_unidade'] ?? null;
    $medQtd      = $input['med_qtd'] ?? 1;

    if (!$patientId || !$categoriaId || empty($descricao) || $valor <= 0) {
        json(['success' => false, 'message' => 'Preencha os campos obrigatórios.']);
        exit;
    }

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            INSERT INTO finance_expenses 
            (patient_id, caregiver_id, categoria_id, descricao, valor, data_despesa, recorrente,
             med_tipo_embalagem, med_conteudo, med_unidade, med_quantidade_comprada)
            VALUES (:pid, :cid, :catid, :desc, :val, :dt, :rec, :m_tipo, :m_cont, :m_uni, :m_qtd)
        ");
        
        $stmt->execute([
            ':pid'   => $patientId,
            ':cid'   => $caregiverId,
            ':catid' => $categoriaId,
            ':desc'  => $descricao,
            ':val'   => $valor,
            ':dt'    => $dataDespesa,
            ':rec'   => $recorrente,
            // Novos binds
            ':m_tipo' => $medTipo,
            ':m_cont' => $medConteudo,
            ':m_uni'  => $medUnidade,
            ':m_qtd'  => $medQtd
        ]);

        $financeId = $pdo->lastInsertId();

        // Se for pendência, atualiza origem
        if ($originId && $originType) {
            if ($originType === 'drug') {
                $upd = $pdo->prepare("UPDATE medicamentos_prescritos SET finance_expense_id = :fid WHERE id = :oid");
            } elseif ($originType === 'exam') {
                $upd = $pdo->prepare("UPDATE AGENDA_EXAM_CON_PROC SET finance_expense_id = :fid WHERE id = :oid");
            }
            if (isset($upd)) $upd->execute([':fid' => $financeId, ':oid' => $originId]);
        }

        $pdo->commit();
        json(['success' => true, 'message' => 'Despesa registrada com sucesso!']);
    } catch (Exception $e) {
        $pdo->rollBack();
        json(['success' => false, 'message' => 'Erro DB: ' . $e->getMessage()]);
    }
}

 // 2a. Buscar Itens Pendentes (Particular)
if ($action === 'finance-get-pending-items') {
    $patientId = $_GET['patient_id'] ?? $input['patient_id'] ?? null;

    if (!$patientId) {
        json(['success' => false, 'message' => 'ID do paciente necessário.']);
        exit;
    }

    try {
        $pendencias = [];

        // 1. Buscar Medicamentos Particulares não lançados
        // CORREÇÃO: A coluna no banco é 'paciente_id', não 'patient_id'
        $stmt = $pdo->prepare("
            SELECT id, nome_medicamento as descricao, 'drug' as origin_type, data_hora_inicio as data_ref
            FROM medicamentos_prescritos 
            WHERE paciente_id = :pid 
            AND status_pagador = 'Particular' 
            AND finance_expense_id IS NULL
        ");
        $stmt->execute([':pid' => $patientId]);
        $meds = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // 2. Buscar Agenda (Exames/Consultas) Particulares não lançados
        // CORREÇÃO: A coluna no banco é 'paciente_id', não 'patient_id'
        $stmt = $pdo->prepare("
            SELECT agendamento_id as id, descricao as descricao, 'exam' as origin_type, data_consulta as data_ref
            FROM AGENDA_EXAM_CON_PROC 
            WHERE paciente_id = :pid 
            AND status_pagador = 'Particular' 
            AND finance_expense_id IS NULL
        ");
        $stmt->execute([':pid' => $patientId]);
        $exams = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Mesclar e formatar para o frontend
        $pendencias = array_merge($meds, $exams);
        
        // Opcional: Adicionar um prefixo para identificar na lista e tratar datas nulas
        foreach ($pendencias as &$p) {
            $tipo = ($p['origin_type'] === 'drug') ? '[Medicamento]' : '[Agenda]';
            
            // Tratamento de segurança para data (caso venha null)
            $dataStr = $p['data_ref'] ?? date('Y-m-d');
            $data = date('d/m/Y', strtotime($dataStr));
            
            $p['label_view'] = "$tipo {$p['descricao']} ($data)";
        }

        json(['success' => true, 'pendencias' => $pendencias]);

    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao buscar pendências: ' . $e->getMessage()]);
    }
}

// 4. Relatório Financeiro (Dashboard)
// 4. Relatório Financeiro (Dashboard) - CORRIGIDO
if ($action === 'finance-get-report') {
    // Busca ID tanto do GET quanto do POST (para garantir compatibilidade)
    $patientId = $_GET['patient_id'] ?? $input['patient_id'] ?? null;
    
    // Obtém o mês do filtro ou usa o atual (Formato esperado: 'YYYY-MM', ex: '2025-12')
    $mesInput = $_GET['mes'] ?? date('Y-m'); 
    
    if (!$patientId) {
        json(['success' => false, 'message' => 'ID do paciente necessário.']);
        exit;
    }

    // Tratamento robusto da data: Separa Ano e Mês
    // Isso evita o erro de "Truncated incorrect DECIMAL value"
    $ano = date('Y');
    $mes = date('m');
    
    if (strpos($mesInput, '-') !== false) {
        $parts = explode('-', $mesInput);
        if (count($parts) == 2) {
            $ano = $parts[0];
            $mes = $parts[1];
        }
    }

    try {
        // A. Buscar despesas do mês
        // ALTERADO: Uso de YEAR() e MONTH() em vez de DATE_FORMAT() para maior segurança SQL
        $stmt = $pdo->prepare("
            SELECT d.*, c.nome as categoria_nome, c.icone, c.cor
            FROM finance_expenses d
            JOIN finance_categories c ON d.categoria_id = c.id
            WHERE d.patient_id = :pid
            AND YEAR(d.data_despesa) = :ano
            AND MONTH(d.data_despesa) = :mes
            ORDER BY d.data_despesa DESC, d.criado_em DESC
        ");
        
        $stmt->execute([
            ':pid' => $patientId, 
            ':ano' => $ano,
            ':mes' => $mes
        ]);
        
        $despesas = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // B. Calcular Totais
        $totalGeral = 0;
        $porCategoria = [];

        foreach ($despesas as $d) {
            $val = (float)$d['valor'];
            $totalGeral += $val;
            
            $catId = $d['categoria_id'];
            if (!isset($porCategoria[$catId])) {
                $porCategoria[$catId] = [
                    'nome' => $d['categoria_nome'],
                    'cor' => $d['cor'],
                    'total' => 0
                ];
            }
            $porCategoria[$catId]['total'] += $val;
        }

        // Formatar valores para frontend
        json([
            'success' => true,
            'periodo' => "$ano-$mes",
            'total_geral' => $totalGeral,
            'despesas' => $despesas,
            'grafico' => array_values($porCategoria)
        ]);

    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao gerar relatório: ' . $e->getMessage()]);
    }
}

// relatório com a soma por cuidador
if ($action === 'finance-get-report-complete') {
    // 1. Busca ID e Mês (Mantém compatibilidade GET/POST)
    $patientId = $_GET['patient_id'] ?? $input['patient_id'] ?? null;
    $mesInput = $_GET['mes'] ?? date('Y-m'); 
    
    if (!$patientId) {
        json(['success' => false, 'message' => 'ID do paciente necessário.']);
        exit;
    }

    // 2. Tratamento de Data (Ano e Mês)
    $ano = date('Y');
    $mes = date('m');
    
    if (strpos($mesInput, '-') !== false) {
        $parts = explode('-', $mesInput);
        if (count($parts) == 2) {
            $ano = $parts[0];
            $mes = $parts[1];
        }
    }

    try {
        // A. Buscar despesas do mês (Lista detalhada com JOIN em Users)
        $sqlLista = "
            SELECT 
                d.*, 
                c.nome as categoria_nome, 
                c.icone, 
                c.cor,
                u.nickname as nome_cuidador
            FROM finance_expenses d
            JOIN finance_categories c ON d.categoria_id = c.id
            LEFT JOIN users u ON d.caregiver_id = u.id
            WHERE d.patient_id = :pid
            AND YEAR(d.data_despesa) = :ano
            AND MONTH(d.data_despesa) = :mes
            ORDER BY d.data_despesa DESC, d.criado_em DESC
        ";

        $stmt = $pdo->prepare($sqlLista);
        $stmt->execute([
            ':pid' => $patientId, 
            ':ano' => $ano,
            ':mes' => $mes
        ]);
        
        $despesas = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // B. Calcular Totais Gerais e Dados do Gráfico de Categorias
        $totalGeral = 0;
        $porCategoria = [];

        foreach ($despesas as $d) {
            $val = (float)$d['valor'];
            $totalGeral += $val;
            
            $catId = $d['categoria_id'];
            if (!isset($porCategoria[$catId])) {
                $porCategoria[$catId] = [
                    'nome' => $d['categoria_nome'],
                    'cor' => $d['cor'],
                    'total' => 0
                ];
            }
            $porCategoria[$catId]['total'] += $val;
        }

        // C. Calcular Totais por Cuidador (Novo Gráfico)
        $sqlCuidadores = "
            SELECT 
                u.nickname as nome, 
                SUM(d.valor) as total
            FROM finance_expenses d
            LEFT JOIN users u ON d.caregiver_id = u.id
            WHERE d.patient_id = :pid
            AND YEAR(d.data_despesa) = :ano
            AND MONTH(d.data_despesa) = :mes
            GROUP BY d.caregiver_id
        ";

        $stmtCuidador = $pdo->prepare($sqlCuidadores);
        $stmtCuidador->execute([
            ':pid' => $patientId, 
            ':ano' => $ano,
            ':mes' => $mes
        ]);
        
        $resumoCuidadores = $stmtCuidador->fetchAll(PDO::FETCH_ASSOC);

        // Tratamento para cuidadores sem nome
        foreach ($resumoCuidadores as &$rc) {
            if (empty($rc['nome'])) {
                $rc['nome'] = 'Não Identificado';
            }
            $rc['total'] = (float)$rc['total'];
        }

        // D. Retorno JSON Final
        json([
            'success' => true,
            'periodo' => "$ano-$mes",
            'total_geral' => $totalGeral,
            'despesas' => $despesas,
            
            // CORREÇÃO AQUI:
            // Usamos a chave 'grafico' para manter compatibilidade com o JS antigo das categorias
            'grafico' => array_values($porCategoria), 
            
            // Nova chave para o novo gráfico de cuidadores
            'resumo_cuidadores' => $resumoCuidadores 
        ]);

    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao gerar relatório: ' . $e->getMessage()]);
    }
}

// ==========================================
// MÓDULO CHECKLIST DE DIREITOS E BENEFÍCIOS
// ==========================================

// 5. Buscar Checklist (Estrutura + Status do Paciente)
if ($action === 'finance-get-checklist') {
    $patientId = $_GET['patient_id'] ?? $input['patient_id'] ?? null;
    // 1. Captura o idioma (padrão 'pt')
    $lang = $_GET['lang'] ?? 'pt'; 
    
    if (!$patientId) {
        json(['success' => false, 'message' => 'ID do paciente necessário.']);
        exit;
    }

    try {
        // A. Definição das Estruturas por Idioma
        // Nota: Os 'id' dos itens DEVEM ser iguais em todos os idiomas para o banco de dados funcionar.
        
        $sections = [];

        // --- INGLÊS (EN) ---
        if ($lang === 'en') {
            $sections = [
                'seguranca' => [
                    'titulo' => '🔒 Security & Privacy',
                    'prioridade' => 'CRITICAL',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'seg_dados', 'texto' => 'Protect Personal Data', 'desc' => 'Share data only on official channels (e.g., hospital reception). Beware of calls or staff asking for passwords/data you already provided.'],
                        ['id' => 'seg_doc', 'texto' => 'Document Backup', 'desc' => 'Keep digital copies of reports, prescriptions, ID, and insurance cards.']
                    ]
                ],
                'hospital' => [
                    'titulo' => '🏥 Hospital & Team',
                    'prioridade' => 'URGENT',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'hosp_assistente', 'texto' => 'Talk to Social Worker', 'desc' => 'Essential step. They guide on rights, exemptions, and local resources.'],
                        ['id' => 'hosp_ouvidora', 'texto' => 'Contact Ombudsman/Quality Audit', 'desc' => 'Keep their contact info to copy on emails when making complaints, suggestions, or praise.'], 
                        ['id' => 'hosp_laudo', 'texto' => 'Request Full Medical Report', 'desc' => 'Must contain ICD (disease code), stage, and diagnosis date (required for benefits).'],
                        ['id' => 'hosp_prontuario', 'texto' => 'Request System Access', 'desc' => 'Ask for online access to the hospital system to track exam results and medical records.'],
                        ['id' => 'hosp_treinamento', 'texto' => 'Resource Training', 'desc' => 'Ask for a demo of available resources: bed control, nurse call, Wi-Fi, TV, playroom, etc.'] 
                    ]
                ],
                'Plano' => [
                    'titulo' => '🏥 Health Insurance',
                    'prioridade' => 'URGENT',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'plano_RH', 'texto' => 'Talk to HR (Corporate)', 'desc' => 'If insurance is corporate, contact your company\'s HR for guidance.'],
                        ['id' => 'plano_assistente', 'texto' => 'Contact Customer Service', 'desc' => 'Verify if the hospital is in-network and experienced in this treatment.'],
                        ['id' => 'plano_cobertura', 'texto' => 'Request Coverage Detail', 'desc' => 'Get a document listing all covered procedures and return deadlines.'],
                        ['id' => 'plano_seg_opiniao', 'texto' => 'Check Second Opinion Channel', 'desc' => 'The insurance must provide a channel for a second medical opinion.']
                    ]
                ],
                'previdencia' => [
                    'titulo' => '💰 Social Security Benefits',
                    'prioridade' => 'URGENT',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'prev_auxilio', 'texto' => 'Sick Pay (Temp. Incapacity)', 'desc' => 'For insured workers absent for more than 15 days.'],
                        ['id' => 'prev_aposentadoria', 'texto' => 'Disability Retirement', 'desc' => 'In cases of permanent incapacity confirmed by expertise.'],
                        ['id' => 'prev_loas', 'texto' => 'Social Assistance (BPC/LOAS)', 'desc' => 'For non-contributors with low family income (requires social analysis).']
                    ]
                ],
                'juridico' => [
                    'titulo' => '⚖️ Legal Assistance',
                    'prioridade' => 'IF NEEDED',
                    'cor' => 'gray',
                    'itens' => [
                        ['id' => 'jur_defensoria', 'texto' => 'Public Defender', 'desc' => 'Free assistance to guarantee denied treatments or medications.'],
                        ['id' => 'jur_liminar', 'texto' => 'Injunction for Treatment', 'desc' => 'Legal action if insurance or public health denies essential meds. Check Anvisa registration first.']
                    ]
                ],
                'associacoes' => [
                    'titulo' => '🤝 Patient Associations',
                    'prioridade' => '1st WEEK',
                    'cor' => 'blue',
                    'itens' => [
                        ['id' => 'assoc_cadastro', 'texto' => 'Register with Support NGOs', 'desc' => 'Search for NGOs specific to your cancer type (e.g., Oncoguia, Abrale, etc).'],
                        ['id' => 'assoc_beneficios', 'texto' => 'Check for Donations', 'desc' => 'Many offer wigs, prostheses, supplements, and food baskets. Check local communities too.']
                    ]
                ],
                'medicamentos' => [
                    'titulo' => '💊 Free Medications',
                    'prioridade' => 'URGENT (High Cost)',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'med_farmacia_pop', 'texto' => 'Popular Pharmacy', 'desc' => 'Discounts or free basic meds (hypertension, asthma, etc).'],
                        ['id' => 'med_alto_custo', 'texto' => 'High Cost Pharmacy (Public)', 'desc' => 'Administrative process to receive special oral chemotherapy.'],
                        ['id' => 'med_importado', 'texto' => 'Imported Meds Request', 'desc' => 'Hospitals cannot sell imported meds without registration. Request a prescription and import directly from the manufacturer obeying Customs rules.']
                    ]
                ],
                'fiscal' => [
                    'titulo' => '📋 Tax Exemptions',
                    'prioridade' => '1st MONTH',
                    'cor' => 'green',
                    'itens' => [
                        ['id' => 'fisc_ir', 'texto' => 'Income Tax Exemption', 'desc' => 'On retirement or pension (even if returning to work).'],
                        ['id' => 'fisc_carro', 'texto' => 'Car Purchase (Tax Relief)', 'desc' => 'If there is physical/motor sequel limiting driving (includes non-drivers).'],
                        ['id' => 'fisc_fgts', 'texto' => 'FGTS / PIS Withdrawal', 'desc' => 'Allowed for workers with cancer or who have a dependent with cancer.']
                    ]
                ],
                'logistica' => [
                    'titulo' => '🏠 Lodging & Transport',
                    'prioridade' => 'IF TREATING AWAY',
                    'cor' => 'yellow',
                    'itens' => [
                        ['id' => 'log_tfd', 'texto' => 'TFD (Out of Home Treatment)', 'desc' => 'Cost aid for intercity/interstate travel. Check special airline programs.'],
                        ['id' => 'log_casa_apoio', 'texto' => 'Support Houses', 'desc' => 'Free or solidarity housing near major hospitals.'],
                        ['id' => 'log_homecare', 'texto' => 'Homecare Adaptation', 'desc' => 'Adapt home routine: online groceries, water filters, mosquito nets, disinfection mats, HEPA filters, legal medical equipment, masks/gel, etc.']
                    ]
                ],
                'apoio' => [
                    'titulo' => '👨‍👩‍👧‍👦 Support Network & Crowdfunding',
                    'prioridade' => 'AS NEEDED',
                    'cor' => 'pink',
                    'itens' => [
                        ['id' => 'apoio_vaquinha', 'texto' => 'Create Online Campaign', 'desc' => 'For extra costs not covered. Be transparent with expenses (use Acura reports).'],
                        ['id' => 'apoio_revezamento', 'texto' => 'Relay Schedule', 'desc' => 'Organize friends/family for hospital shifts and add them as caregivers in Acura.'],
                        ['id' => 'apoio_enfermagem', 'texto' => 'Friendly Nursing', 'desc' => 'Include nursing professionals and volunteers as caregivers when there is a trusted agreement.']
                    ]
                ]
            ];
        }
        
        // --- ESPANHOL (ES) ---
        elseif ($lang === 'es') {
            $sections = [
                'seguranca' => [
                    'titulo' => '🔒 Seguridad y Privacidad',
                    'prioridade' => 'CRÍTICO',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'seg_dados', 'texto' => 'Proteger Datos Personales', 'desc' => 'Divulgue datos solo en canales oficiales. Cuidado con llamadas pidiendo contraseñas que ya informó en recepción.'],
                        ['id' => 'seg_doc', 'texto' => 'Respaldo de Documentos', 'desc' => 'Tenga copias digitales de informes, recetas, identificación y tarjetas de seguro.']
                    ]
                ],
                'hospital' => [
                    'titulo' => '🏥 Hospital y Equipo',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'hosp_assistente', 'texto' => 'Hablar con Trabajo Social', 'desc' => 'Fundamental. Orientan sobre derechos, exenciones y recursos locales.'],
                        ['id' => 'hosp_ouvidora', 'texto' => 'Contactar Defensoría/Calidad', 'desc' => 'Tenga el contacto para copiar en correos electrónicos al hacer quejas o sugerencias.'], 
                        ['id' => 'hosp_laudo', 'texto' => 'Solicitar Informe Médico Completo', 'desc' => 'Debe contener CIE (código de enfermedad), estadio y fecha de diagnóstico.'],
                        ['id' => 'hosp_prontuario', 'texto' => 'Solicitar acceso al sistema', 'desc' => 'Pida acceso online para seguir resultados de exámenes e historial médico.'],
                        ['id' => 'hosp_treinamento', 'texto' => 'Entrenamiento de recursos', 'desc' => 'Solicite demostración de recursos: control de cama, llamada a enfermería, Wi-Fi, etc.'] 
                    ]
                ],
                'Plano' => [
                    'titulo' => '🏥 Seguro Médico',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'plano_RH', 'texto' => 'Hablar con RRHH (corporativo)', 'desc' => 'Si es seguro empresarial, contacte a RRHH para orientación.'],
                        ['id' => 'plano_assistente', 'texto' => 'Hablar con Atención al Cliente', 'desc' => 'Verifique si el hospital está en la red y tiene experiencia en el tratamiento.'],
                        ['id' => 'plano_cobertura', 'texto' => 'Solicitar detalle de cobertura', 'desc' => 'Documento con todos los procedimientos cubiertos y plazos.'],
                        ['id' => 'plano_seg_opiniao', 'texto' => 'Verificar canal de segunda opinión', 'desc' => 'El seguro debe proveer canal para segunda opinión médica.']
                    ]
                ],
                'previdencia' => [
                    'titulo' => '💰 Beneficios Previsionales',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'prev_auxilio', 'texto' => 'Subsidio por Enfermedad', 'desc' => 'Para asegurados alejados por más de 15 días.'],
                        ['id' => 'prev_aposentadoria', 'texto' => 'Jubilación por Invalidez', 'desc' => 'En casos de incapacidad permanente confirmada.'],
                        ['id' => 'prev_loas', 'texto' => 'Asistencia Social (BPC)', 'desc' => 'Para quien no contribuye y tiene baja renta (requiere análisis).']
                    ]
                ],
                'juridico' => [
                    'titulo' => '⚖️ Asistencia Legal',
                    'prioridade' => 'SI ES NECESARIO',
                    'cor' => 'gray',
                    'itens' => [
                        ['id' => 'jur_defensoria', 'texto' => 'Defensoría Pública', 'desc' => 'Asistencia gratuita para garantizar tratamientos negados.'],
                        ['id' => 'jur_liminar', 'texto' => 'Medida Cautelar', 'desc' => 'Acción judicial si niegan medicación esencial.']
                    ]
                ],
                'associacoes' => [
                    'titulo' => '🤝 Asociaciones de Pacientes',
                    'prioridade' => '1ª SEMANA',
                    'cor' => 'blue',
                    'itens' => [
                        ['id' => 'assoc_cadastro', 'texto' => 'Registrarse en ONG de Apoyo', 'desc' => 'Busque ONGs específicas de su tipo de cáncer.'],
                        ['id' => 'assoc_beneficios', 'texto' => 'Verificar Donaciones', 'desc' => 'Muchas ofrecen pelucas, prótesis, suplementos y canastas básicas.']
                    ]
                ],
                'medicamentos' => [
                    'titulo' => '💊 Medicamentos Gratuitos',
                    'prioridade' => 'URGENTE (Alto Costo)',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'med_farmacia_pop', 'texto' => 'Farmacia Popular', 'desc' => 'Descuentos o gratuidad en remedios básicos.'],
                        ['id' => 'med_alto_custo', 'texto' => 'Farmacia de Alto Costo (Pública)', 'desc' => 'Proceso administrativo para recibir quimioterapia oral especial.'],
                        ['id' => 'med_importado', 'texto' => 'Importación de Medicamentos', 'desc' => 'Solicite receta e importe directamente del fabricante obedeciendo reglas de Aduana.']
                    ]
                ],
                'fiscal' => [
                    'titulo' => '📋 Exenciones Fiscales',
                    'prioridade' => '1º MES',
                    'cor' => 'green',
                    'itens' => [
                        ['id' => 'fisc_ir', 'texto' => 'Exención de Impuesto a la Renta', 'desc' => 'Sobre jubilación o pensión.'],
                        ['id' => 'fisc_carro', 'texto' => 'Compra de Auto (Impuestos)', 'desc' => 'Si hay secuela física/motora (incluye no conductor).'],
                        ['id' => 'fisc_fgts', 'texto' => 'Retiro de Fondos (FGTS)', 'desc' => 'Permitido para el trabajador con cáncer o dependiente.']
                    ]
                ],
                'logistica' => [
                    'titulo' => '🏠 Hospedaje y Transporte',
                    'prioridade' => 'SI TRATA FUERA',
                    'cor' => 'yellow',
                    'itens' => [
                        ['id' => 'log_tfd', 'texto' => 'Tratamiento Fuera del Domicilio', 'desc' => 'Ayuda de costo para viajes. Vea programas con aerolíneas.'],
                        ['id' => 'log_casa_apoio', 'texto' => 'Casas de Apoyo', 'desc' => 'Hospedaje gratuito o solidario cerca de grandes hospitales.'],
                        ['id' => 'log_homecare', 'texto' => 'Adaptación del Hogar', 'desc' => 'Adapte la rutina: compras online, filtros de agua, mosquiteros, desinfección, filtro HEPA, equipos médicos legales, mascarillas/gel, etc.']
                    ]
                ],
                'apoio' => [
                    'titulo' => '👨‍👩‍👧‍👦 Red de Apoyo',
                    'prioridade' => 'CUANDO NECESITE',
                    'cor' => 'pink',
                    'itens' => [
                        ['id' => 'apoio_vaquinha', 'texto' => 'Crear Colecta Online', 'desc' => 'Para costos extras. Sea transparente con los gastos.'],
                        ['id' => 'apoio_revezamento', 'texto' => 'Escala de Turnos', 'desc' => 'Organice amigos/familia para turnos y agréguelos como cuidadores.'],
                        ['id' => 'apoio_enfermagem', 'texto' => 'Enfermería amiga', 'desc' => 'Incluya profesionales de enfermería como cuidadores si hay acuerdo.']
                    ]
                ]
            ];
        }
        
        // --- PORTUGUÊS (PT) - Padrão ---
        else {
            $sections = [
                'seguranca' => [
                    'titulo' => '🔒 Segurança e Privacidade',
                    'prioridade' => 'CRÍTICO',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'seg_dados', 'texto' => 'Proteger dados pessoais', 'desc' => 'Divulgue dados apenas em canais oficiais (exemplo: recepção do hospital e e-mail com domínio @sitedohospital). Cuidado com ligações ou profissionais de saúde no leito pedindo dados e senhas que você informou na recepção e já deveriam estar no sistema do hospital.'],
                        ['id' => 'seg_doc', 'texto' => 'Backup de Documentos', 'desc' => 'Tenha cópias digitais de laudos, receitas, RG e cartão do plano e do governo.']
                    ]
                ],
                'hospital' => [
                    'titulo' => '🏥 Hospital e Equipe',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'hosp_assistente', 'texto' => 'Falar com Assistente Social', 'desc' => 'Passo fundamental. Ela orienta sobre TFD, isenções e recursos locais.'],
                        ['id' => 'hosp_ouvidora', 'texto' => 'Falar com Ouvidoria e Auditor de Qualidade', 'desc' => 'Tenha o contato da ouvidoria e do setor de controle de qualidade para copiar em comunicações por e-mail na hora de fazer uma queixa, sugestão ou elogio.'], 
                        ['id' => 'hosp_laudo', 'texto' => 'Solicitar Laudo Médico Completo', 'desc' => 'Deve conter CID (código internacional da doença), estágio e data do diagnóstico (necessário para todos os benefícios).'],
                        ['id' => 'hosp_prontuario', 'texto' => 'Solicitar acesso ao sistema', 'desc' => 'Peça acesso ao sistema online do hospital para acompanhar resultados de exames e o prontuário médico.'],
                        ['id' => 'hosp_treinamento', 'texto' => 'Treinamento de recursos', 'desc' => 'Solicite ao hospital um treinamento/demonstração dos recursos disponíveis, como controle da cama, chamada de enfermagem, senha do wifi, uso da televisão, brinquedoteca, etc.'] 
                    ]
                ],
                'Plano' => [
                    'titulo' => '🏥 Plano',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'plano_RH', 'texto' => 'Falar com RH (corporativo)', 'desc' => 'Se o plano é coorporativo, entre em contato com o setor de recursos humanos da sua empresa para obter orientações.'],
                        ['id' => 'plano_assistente', 'texto' => 'Falar com Atendimento', 'desc' => 'Passo importante. Verificar se o hospital é credenciado e se possui experiência para o tratamento.'],
                        ['id' => 'plano_cobertura', 'texto' => 'Solicitar contrato e detalhamento de cobertura', 'desc' => 'Deve ter um termo com todos os procedimentos cobertos e os prazos de retorno.'] ,
                        ['id' => 'plano_seg_opiniao', 'texto' => 'Verificar canal de segunda opinião médica', 'desc' => 'O plano deve prover canal de segunda opinião médica.']
                    ]
                ],
                'previdencia' => [
                    'titulo' => '💰 Benefícios Previdenciários',
                    'prioridade' => 'URGENTE',
                    'cor' => 'orange',
                    'itens' => [
                        ['id' => 'prev_auxilio', 'texto' => 'Auxílio-Doença (Incapacidade Temp.)', 'desc' => 'Para segurados do INSS afastados por mais de 15 dias.'],
                        ['id' => 'prev_aposentadoria', 'texto' => 'Aposentadoria por Invalidez', 'desc' => 'Em casos de incapacidade permanente confirmada por perícia.'],
                        ['id' => 'prev_loas', 'texto' => 'BPC / LOAS', 'desc' => 'Para quem não contribui e tem baixa renda familiar (requer análise social).']
                    ]
                ],
                'juridico' => [
                    'titulo' => '⚖️ Assistência Jurídica',
                    'prioridade' => 'SE NECESSÁRIO',
                    'cor' => 'gray',
                    'itens' => [
                        ['id' => 'jur_defensoria', 'texto' => 'Defensoria Pública', 'desc' => 'Assistência gratuita para garantir tratamentos negados ou medicamentos.'],
                        ['id' => 'jur_liminar', 'texto' => 'Liminar de Tratamento', 'desc' => 'Ação judicial caso o plano ou SUS negue medicação essencial. Obs.: confira antes se o medicamento tem registro na Anvisa.']
                    ]
                ],
                'associacoes' => [
                    'titulo' => '🤝 Associações de Pacientes',
                    'prioridade' => '1ª SEMANA',
                    'cor' => 'blue',
                    'itens' => [
                        ['id' => 'assoc_cadastro', 'texto' => 'Cadastrar em ONG de Apoio', 'desc' => 'Busque ONGs específicas do seu tipo de câncer (Ex: Oncoguia, Abrale, GAPC, ABRAPEC, AMO - Associação dos Amigos da Oncologia, Aapecan, Coniacc, Instituto Vencer o Câncer, associacaopresente.org.br, dentre outras).'],
                        ['id' => 'assoc_beneficios', 'texto' => 'Verificar Doações', 'desc' => 'Muitas oferecem perucas, próteses, suplementos e cestas básicas. Olhe também em sua igreja e comunidade.']
                    ]
                ],
                'medicamentos' => [
                    'titulo' => '💊 Medicamentos Gratuitos',
                    'prioridade' => 'URGENTE (Alto Custo)',
                    'cor' => 'red',
                    'itens' => [
                        ['id' => 'med_farmacia_pop', 'texto' => 'Farmácia Popular', 'desc' => 'Descontos ou gratuidade em remédios básicos (hipertensão, asma, etc).'],
                        ['id' => 'med_alto_custo', 'texto' => 'Farmácia de Alto Custo (SUS)', 'desc' => 'Processo administrativo para receber quimioterápicos orais ou especiais.'],
                        ['id' => 'med_importado', 'texto' => 'Solicitar receita médica e dados para importação de medicação', 'desc' => 'Hospitais são proibidos de vender medicação importada sem registro na Anvisa. Solicite receita médica e faça a importação direta com a fabricante obedecendo as regras da Alfândega.']
                    ]
                ],
                'fiscal' => [
                    'titulo' => '📋 Isenções Fiscais',
                    'prioridade' => '1º MÊS',
                    'cor' => 'green',
                    'itens' => [
                        ['id' => 'fisc_ir', 'texto' => 'Isenção de Imposto de Renda', 'desc' => 'Sobre aposentadoria, reforma ou pensão (mesmo se voltar a trabalhar).'],
                        ['id' => 'fisc_carro', 'texto' => 'Compra de Carro (IPI/ICMS)', 'desc' => 'Se houver sequela física ou motora que limite a direção (inclui não condutor).'],
                        ['id' => 'fisc_fgts', 'texto' => 'Saque do FGTS / PIS', 'desc' => 'Permitido para o trabalhador com câncer ou que tenha dependente com câncer.']
                    ]
                ],
                'logistica' => [
                    'titulo' => '🏠 Hospedagem e Transporte',
                    'prioridade' => 'SE TRATAR FORA',
                    'cor' => 'yellow',
                    'itens' => [
                        ['id' => 'log_tfd', 'texto' => 'TFD (Tratamento Fora de Domicílio)', 'desc' => 'Ajuda de custo do SUS para viagens interestaduais/intermunicipais. Também veja programas especiais com companhias aéreas[exemplo: Azul, American Airlines]'],
                        ['id' => 'log_casa_apoio', 'texto' => 'Casas de Apoio', 'desc' => 'Hospedagem gratuita ou solidária próxima aos grandes hospitais. Pesquise na localidade onde se encontra'],
                        ['id' => 'log_homecare', 'texto' => 'Homecare', 'desc' => 'Adapte a rotina de sua casa. Por exemplo: faça compras de supermercado online para poupar tempo e reduzir exposição pública, filtre ou compre água mineral, coloque tela mosqueteira nas janelas, use tapete com desinfetante na porta, tenha lavadoura termodesinfectora de louças, use robô de limpeza com desinfetante de chão durante a noite, use filtro de ar HEPA no quarto de dormir, tenha equipamentos médicos legalizados (ex: termômetro, aparelho de pressão, glicosímetro com registro na Anvisa), troque o filtro de ar da cabine do carro regularmente, use máscara e álcool gel várias vezes ao dia, etc. ']                    
                    ]
                ],
                 'apoio' => [
                    'titulo' => '👨‍👩‍👧‍👦 Rede de Apoio e Vaquinhas',
                    'prioridade' => 'QUANDO PRECISAR',
                    'cor' => 'pink',
                    'itens' => [
                        ['id' => 'apoio_vaquinha', 'texto' => 'Criar Vaquinha e Campanha Online', 'desc' => 'Para custos extras não cobertos, use os sites como vakinha.com.br, campanhadobem.com.br, gofundme.com. Seja transparente com os gastos [exemplo: use os printscreens de relatórios financeiros aqui do Acura].'],
                        ['id' => 'apoio_revezamento', 'texto' => 'Escala de Revezamento', 'desc' => 'Organize amigos/família para turnos no hospital e os inclua como cuidadores aqui no Acura. Não faça tudo sozinho(a).'],
                        ['id' => 'apoio_enfermagem', 'texto' => 'Enfermagem amiga', 'desc' => 'Inclua profissionais de enfermagem e voluntários como cuidadores quando houver acordo confiável entre as partes.'], 
                    ]
                ]
            ];
        }

        

        // B. Buscar Status Salvos no Banco
        $stmt = $pdo->prepare("SELECT nome_beneficio, status FROM finance_benefits_status WHERE patient_id = :pid");
        $stmt->execute([':pid' => $patientId]);
        $savedStatus = $stmt->fetchAll(PDO::FETCH_KEY_PAIR); // Retorna array [ 'id_item' => 'status' ]

        json(['success' => true, 'structure' => $sections, 'saved_status' => $savedStatus]);

    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao carregar checklist: ' . $e->getMessage()]);
    }
}

// 6. Atualizar Status do Item (Check/Uncheck)
if ($action === 'finance-toggle-benefit') {
    $patientId = $input['patient_id'] ?? null;
    $itemId = $input['item_id'] ?? null;
    $checked = $input['checked'] ?? false; // true ou false
    
    if (!$patientId || !$itemId) {
        json(['success' => false, 'message' => 'Dados incompletos.']);
        exit;
    }

    $status = $checked ? 'aprovado' : 'nao_iniciado';

    try {
        // Verifica se já existe
        $stmt = $pdo->prepare("SELECT id FROM finance_benefits_status WHERE patient_id = :pid AND nome_beneficio = :nome");
        $stmt->execute([':pid' => $patientId, ':nome' => $itemId]);
        $exists = $stmt->fetch();

        if ($exists) {
            $upd = $pdo->prepare("UPDATE finance_benefits_status SET status = :st, data_atualizacao = NOW() WHERE id = :id");
            $upd->execute([':st' => $status, ':id' => $exists['id']]);
        } else {
            $ins = $pdo->prepare("INSERT INTO finance_benefits_status (patient_id, nome_beneficio, status) VALUES (:pid, :nome, :st)");
            $ins->execute([':pid' => $patientId, ':nome' => $itemId, ':st' => $status]);
        }

        json(['success' => true, 'new_status' => $status]);

    } catch (Exception $e) {
        json(['success' => false, 'message' => 'Erro ao atualizar: ' . $e->getMessage()]);
    }
}

// 7. Cadastro de Profissional de Saúde (Médico/Enfermeiro)
if ($action === 'register-professional') {
    $input = json_decode(file_get_contents('php://input'), true);

    // --- DADOS DO PROFISSIONAL ---
    $nome = trim($input['nome'] ?? '');
    $tipo_conselho = $input['tipo_conselho'] ?? null;
    $numero_conselho = $input['numero_conselho'] ?? null;
    $formacao = $input['formacao'] ?? null;
    $pronome_tratamento = $input['pronome_tratamento'] ?? null;
    $email = filter_var($input['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $telefone = $input['telefone'] ?? null; 
    $is_cuidador = $input['is_cuidador'] ?? false;

    // --- DADOS DE RASTREABILIDADE E CONTEXTO ---
    $currentUserId = $input['user_id'] ?? null;
    $patientId = $input['patient_id'] ?? null;
    
    // Geolocalização
    $latitude = $input['latitude'] ?? null;
    $longitude = $input['longitude'] ?? null;

    // Validação básica
    if (!$nome || !$tipo_conselho || !$numero_conselho || !$formacao || !$pronome_tratamento || !$email) {
        json(['success' => false, 'message' => 'Dados obrigatórios incompletos ou e-mail inválido.']);
        exit;
    }

    if (!$currentUserId || !$patientId) {
        json(['success' => false, 'message' => 'Erro de contexto: Cuidador ou Paciente não identificados.']);
        exit;
    }

    try {
        // 1. Contexto para o E-mail: Busca nomes
        $stmtC = $pdo->prepare("SELECT nickname FROM users WHERE id = :uid LIMIT 1");
        $stmtC->execute([':uid' => $currentUserId]);
        $cuidador = $stmtC->fetch(PDO::FETCH_ASSOC);
        $nomeCuidador = $cuidador['nickname'] ?? 'Um Cuidador';

        $stmtP = $pdo->prepare("SELECT nickname FROM patients WHERE id = :pid LIMIT 1");
        $stmtP->execute([':pid' => $patientId]);
        $paciente = $stmtP->fetch(PDO::FETCH_ASSOC);
        $nomePaciente = $paciente['nickname'] ?? 'o paciente';

        // =================================================================================
        // 2. BLOQUEIO DE DUPLICIDADE (Verificação Inteligente)
        // =================================================================================
        // Verifica se já existe por (Conselho + Tipo) OU (Email)
        $stmtCheck = $pdo->prepare("
            SELECT id, email, nome 
            FROM profissionais_saude 
            WHERE (numero_conselho = :nc AND tipo_conselho = :tc) 
               OR email = :email 
            LIMIT 1
        ");
        $stmtCheck->execute([
            ':nc' => $numero_conselho,
            ':tc' => $tipo_conselho,
            ':email' => $email
        ]);
        
        $profissionalExistente = $stmtCheck->fetch(PDO::FETCH_ASSOC);
        $profissionalId = null;
        $novoCadastro = false;

        if ($profissionalExistente) {
            // Se já existe, usamos o ID dele e NÃO inserimos de novo
            $profissionalId = $profissionalExistente['id'];
            $novoCadastro = false;
        } else {
            // Se não existe, fazemos o INSERT normalmente
            $sql = "INSERT INTO profissionais_saude 
                    (nome, tipo_conselho, numero_conselho, formacao, pronome_tratamento, email, telefone, is_cuidador, registered_by_user_id, registration_lat, registration_lon)
                    VALUES 
                    (:nome, :tipo_conselho, :numero_conselho, :formacao, :pronome_tratamento, :email, :telefone, :is_cuidador, :reg_by, :lat, :lon)";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':nome' => $nome,
                ':tipo_conselho' => $tipo_conselho,
                ':numero_conselho' => $numero_conselho,
                ':formacao' => $formacao,
                ':pronome_tratamento' => $pronome_tratamento,
                ':email' => $email,
                ':telefone' => $telefone,
                ':is_cuidador' => $is_cuidador ? 1 : 0,
                ':reg_by' => $currentUserId,
                ':lat' => $latitude,
                ':lon' => $longitude
            ]);
            
            $profissionalId = $pdo->lastInsertId();
            $novoCadastro = true;
        }

        // 3. Vincular Profissional ao Paciente
        // O IGNORE garante que se o vínculo já existir, não dá erro
        $stmtLink = $pdo->prepare("INSERT IGNORE INTO patient_professionals (patient_id, profissional_id) VALUES (:pid, :prof_id)");
        $stmtLink->execute([':pid' => $patientId, ':prof_id' => $profissionalId]);

        // 4. Lógica de Envio de E-mail
        // Verifica se o médico tem USUÁRIO (login) no sistema
        $stmtUser = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $stmtUser->execute([':email' => $email]);
        $userMedico = $stmtUser->fetch(PDO::FETCH_ASSOC);

        $assunto = "Você foi referenciado no Acura Vencer Cuidando";
        $emailEnviado = false;

        if ($userMedico) {
            // CENÁRIO A: Médico já é usuário do sistema
            // (Seja ele novo na tabela de profissionais ou antigo, se ele tem login, mandamos aviso de vínculo)
            $msg = "Olá, <b>$pronome_tratamento $nome</b>.<br><br>" .
                   "O cuidador <b>$nomeCuidador</b> adicionou você como profissional responsável pelo paciente <b>$nomePaciente</b>.<br>" .
                   "Acesse sua conta para visualizar os novos dados clínicos disponíveis.";
            $acaoTexto = "Acessar";
            $acaoLink = $URL_APP;
            $acaoLink .= "index.html";
            
            // Só envia se acabou de ser criado o vínculo ou o profissional
            // (Para evitar spam se o cuidador clicar em salvar várias vezes no mesmo médico)
            if ($stmtLink->rowCount() > 0 || $novoCadastro) {
                $htmlEmail = gerarTemplateEmail($assunto, $msg, $acaoTexto, $acaoLink);
                enviarEmailSistema($email, $nome, $assunto, $htmlEmail);
            }

        } else {
            // CENÁRIO B: Médico NÃO tem login (Convite)
            
            // Se for um NOVO cadastro de profissional, mandamos as congratulações
            if ($novoCadastro) {
                $msg = "Olá, <b>$pronome_tratamento $nome</b>.<br><br>" .
                       "Parabéns! Você foi referenciado na nossa plataforma.<br>" .
                       "O cuidador <b>$nomeCuidador</b> indicou você como o profissional ($formacao) responsável por <b>$nomePaciente</b>.<br><br>" .
                       "Para acompanhar a evolução clínica deste paciente, complete seu cadastro gratuito:";
                
                $acaoTexto = "Aceitar Convite";
                $acaoLink = $URL_APP;
                $acaoLink .= "cadastro.html?email=" . urlencode($email) . "&name=" . urlencode($nome);
                
                $htmlEmail = gerarTemplateEmail($assunto, $msg, $acaoTexto, $acaoLink);
                enviarEmailSistema($email, $nome, $assunto, $htmlEmail);
            } 
            // Se o profissional já existia mas foi vinculado a um NOVO paciente agora
            elseif ($stmtLink->rowCount() > 0) {
                 $msg = "Olá, <b>$pronome_tratamento $nome</b>.<br><br>" .
                       "Você foi vinculado a um novo paciente: <b>$nomePaciente</b> (pelo cuidador $nomeCuidador).<br>" .
                       "Identificamos que você ainda não finalizou seu cadastro de acesso.<br>" .
                       "Clique abaixo para criar sua senha e ver os dados:";
                
                $acaoTexto = "Finalizar Cadastro";
                $acaoLink = $URL_APP;
                $acaoLink .= "cadastro.html?email=" . urlencode($email);
                
                $htmlEmail = gerarTemplateEmail($assunto, $msg, $acaoTexto, $acaoLink);
                enviarEmailSistema($email, $nome, $assunto, $htmlEmail);
            }
        }

        json([
            'success' => true, 
            'message' => $novoCadastro ? 'Profissional cadastrado e vinculado!' : 'Profissional já existente foi vinculado ao paciente!', 
            'id' => $profissionalId,
            'is_new' => $novoCadastro
        ]);

    } catch (PDOException $e) {
        error_log('Erro Profissional: ' . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno ao processar cadastro.']);
    }
}

if ($action === 'search-professional') {
    $term = $_GET['term'] ?? '';
    // Recebe as coordenadas do usuário via GET
    $userLat = $_GET['lat'] ?? null;
    $userLon = $_GET['lon'] ?? null;

    // Evita buscas muito curtas para poupar o banco
    if (strlen($term) < 2) {
        json([]); 
        exit;
    }

    try {
        $params = [':term' => "%$term%"];
        
        // Verifica se temos coordenadas válidas para fazer o cálculo de distância
        if (is_numeric($userLat) && is_numeric($userLon)) {
            // --- CONSULTA COM GEOLOCALIZAÇÃO (Fórmula de Haversine) ---
            // 6371 é o raio da Terra em KM.
            // O cálculo retorna a distância na coluna 'distance_km'
            // ORDER BY distance_km ASC garante que os mais próximos apareçam primeiro (raio infinito)
            // Se profissionais tiverem coord NULL, eles aparecem no final ou são excluídos dependendo da lógica (aqui mantemos)
            
            $sql = "
                SELECT 
                    id, 
                    nome, 
                    telefone, 
                    formacao,
                    registration_lat,
                    registration_lon,
                    (6371 * acos(
                        cos(radians(:lat)) * cos(radians(registration_lat)) * cos(radians(registration_lon) - radians(:lon)) + 
                        sin(radians(:lat)) * sin(radians(registration_lat))
                    )) AS distance_km
                FROM profissionais_saude 
                WHERE (nome LIKE :term OR telefone LIKE :term)
                ORDER BY 
                    CASE WHEN distance_km IS NULL THEN 1 ELSE 0 END, -- Joga quem não tem GPS para o final
                    distance_km ASC 
                LIMIT 20
            ";
            
            $params[':lat'] = $userLat;
            $params[':lon'] = $userLon;
            
        } else {
            // --- CONSULTA PADRÃO (SEM GPS) ---
            // Se o usuário negou a localização, buscamos apenas pelo nome
            $sql = "
                SELECT id, nome, telefone, formacao, NULL as distance_km
                FROM profissionais_saude 
                WHERE nome LIKE :term 
                   OR telefone LIKE :term 
                ORDER BY nome ASC
                LIMIT 20
            ";
        }

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Pequeno tratamento para arredondar a distância no PHP antes de enviar
        foreach ($results as &$row) {
            if (isset($row['distance_km']) && $row['distance_km'] !== null) {
                $row['distance_km'] = round($row['distance_km'], 1); // Ex: 12.5 km
            }
        }

        json($results);

    } catch (PDOException $e) {
        error_log("Erro na busca de profissionais: " . $e->getMessage());
        json([]); 
    }
}

// api.php - Adicionar no bloco de POST

if ($action === 'save-attendance-report') {
    // 1. Recebe o JSON enviado pelo JS
    $input = json_decode(file_get_contents('php://input'), true);

    // 2. Validação básica
    if (!$input) {
        echo json_encode(['success' => false, 'message' => 'Dados inválidos.']);
        exit;
    }

    $userId = $input['userId'] ?? null;
    $pacienteId = $input['patientId'] ?? null; // Pode ser null se não tiver paciente selecionado
    
    // Tratamento de dados para evitar erros SQL
    $motivo = $input['reason'] ?? 'Geral';
    $profissional = $input['professional'] ?? 'Não informado';
    $cuidador = $input['caregiver'] ?? 'Não informado';
    $agilidade = $input['agility'] ?? 'N/A';
    $observacoes = $input['notes'] ?? '';
    $localOk = ($input['locationOk'] === true || $input['locationOk'] === 'Sim') ? 1 : 0;
    
    // Data/Hora atual (MySQL format)
    $dataRegistro = date('Y-m-d H:i:s');

    try {
        $sql = "INSERT INTO relatorios_atendimentos 
                (user_id, paciente_id, data_registro, motivo, profissional_nome, cuidador_nome, agilidade, local_ok, observacoes) 
                VALUES 
                (:uid, :pid, :dta, :mot, :prof, :cuid, :agi, :loc, :obs)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':uid' => $userId,
            ':pid' => $pacienteId,
            ':dta' => $dataRegistro,
            ':mot' => $motivo,
            ':prof' => $profissional,
            ':cuid' => $cuidador,
            ':agi' => $agilidade,
            ':loc' => $localOk,
            ':obs' => $observacoes
        ]);

        echo json_encode(['success' => true, 'message' => 'Relatório salvo no servidor.', 'id' => $pdo->lastInsertId()]);

    } catch (PDOException $e) {
        error_log("Erro ao salvar relatório: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Erro ao salvar no banco de dados.']);
    }    
}

/* get-historico-profissionais */
if ($action === 'get-historico-profissionais') {
    try {
        // 1. Captura o ID do paciente enviado pelo JS
        $paciente_id = $_GET['paciente_id'] ?? null;

        if (!$paciente_id) {
            // Se não enviou ID, retorna lista vazia por segurança
            json(['success' => false, 'data' => []]);
            exit;
        }

        // 2. Prepara a query filtrando pelo paciente_id
        $stmt = $pdo->prepare("
            SELECT DISTINCT profissional_nome 
            FROM relatorios_atendimentos 
            WHERE profissional_nome IS NOT NULL 
              AND profissional_nome != '' 
              AND paciente_id = :paciente_id  /* <--- O filtro essencial */
            ORDER BY profissional_nome ASC
        ");
        
        // 3. Executa passando o parâmetro seguro
        $stmt->execute([':paciente_id' => $paciente_id]);
        
        $profissionais = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        json(['success' => true, 'data' => $profissionais]);
        
    } catch (PDOException $e) {
        error_log("Erro ao buscar histórico de profissionais: " . $e->getMessage());
        json(['success' => false, 'data' => []]);
    }
}

//pesquisa drogas no banco de medicamentos
if ($action === 'search-drugs') {
    $term = $_GET['term'] ?? '';
    $lang = $_GET['lang'] ?? 'pt'; // Recebe a língua do frontend (pt, es, en)

    if (strlen($term) < 3) {
        json([]); // Retorna vazio se digitar menos de 3 letras
        exit;
    }

    try {
        // Conexão específica para o banco de medicamentos
        $pdoMed = new PDO("mysql:host=".DB_MED_HOST.";dbname=".DB_MED_NAME.";charset=utf8mb4", DB_MED_USER, DB_MED_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        // Determina qual coluna de nome usar baseado na língua
        $colunaNome = 'nome_pt'; // Padrão
        if ($lang === 'es') $colunaNome = 'nome_es';
        if ($lang === 'en') $colunaNome = 'nome_en_search';

        // Query complexa com JOINS para trazer todos os detalhes solicitados
        // Filtramos apenas registros VÁLIDOS para segurança
        $sql = "
            SELECT 
                p.$colunaNome as nome_medicamento,
                e.nome_empresa as fabricante,
                c.descricao as classe_terapeutica,
                r.descricao as categoria_regulatoria,
                m.numero_registro
            FROM tb_medicamento m
            JOIN tb_produto p ON m.fk_produto = p.id
            JOIN tb_empresa e ON m.fk_empresa = e.id
            LEFT JOIN tb_classe_terapeutica c ON m.fk_classe = c.id
            LEFT JOIN tb_categoria_regulatoria r ON m.fk_categoria = r.id
            WHERE p.$colunaNome LIKE :term
            AND m.situacao = 'VÁLIDO' 
            LIMIT 15
        ";

        $stmt = $pdoMed->prepare($sql);
        $stmt->execute([':term' => "%$term%"]);
        $resultados = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Formata o retorno para o frontend
        $output = [];
        foreach ($resultados as $row) {
            $output[] = [
                'nome' => $row['nome_medicamento'], // O valor limpo para salvar
                'display' => strtoupper($row['nome_medicamento']), // Nome em destaque
                'detalhes' => "Fab: {$row['fabricante']} | Classe: {$row['classe_terapeutica']} | Cat: {$row['categoria_regulatoria']}"
            ];
        }

        json($output);

    } catch (PDOException $e) {
        error_log("Erro ao buscar medicamentos: " . $e->getMessage());
        json([]); // Falha silenciosa para não travar o front
    }
}

// ==========================================
// ESCALA REAL DOS CUIDADORES
// ==========================================

// --- INICIAR ESCALA (Check-in) ---
if ($action === 'shift-start') {
    $input = json_decode(file_get_contents('php://input'), true);
    $pid = $input['patient_id'] ?? null;
    $uid = $input['caregiver_id'] ?? null; 

    if (!$pid || !$uid) { json(['success'=>false, 'message' => 'IDs inválidos']); exit; }

    try {
        // Verifica se já existe um turno ABERTO (status = 'ABERTO')
        // Tabela: escala, Colunas: patient_id, caregiver_id
        $stmtCheck = $pdo->prepare("SELECT id FROM escala WHERE patient_id = :pid AND caregiver_id = :uid AND status = 'ABERTO' LIMIT 1");
        $stmtCheck->execute([':pid' => $pid, ':uid' => $uid]);
        $existing = $stmtCheck->fetch(PDO::FETCH_ASSOC);

        if ($existing) {
            json(['success' => true, 'shift_id' => $existing['id'], 'message' => 'Turno retomado']);
        } else {
            // Insere novo registro
            $sql = "INSERT INTO escala (patient_id, caregiver_id, check_in, status) VALUES (:pid, :uid, NOW(), 'ABERTO')";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':pid' => $pid, ':uid' => $uid]);
            json(['success' => true, 'shift_id' => $pdo->lastInsertId(), 'message' => 'Turno iniciado']);
        }
    } catch (PDOException $e) {
        json(['success' => false, 'message' => $e->getMessage()]);
    }
}

// --- ENCERRAR ESCALA (Check-out) ---
if ($action === 'shift-end') {
    $input = json_decode(file_get_contents('php://input'), true);
    $shiftId = $input['shift_id'] ?? null;
    $motivo = $input['motivo'] ?? 'Encerramento manual';

    if (!$shiftId) { json(['success'=>false]); exit; }

    try {
        // Atualiza check_out e muda status
        $sql = "UPDATE escala SET check_out = NOW(), status = 'FECHADO', obs = :obs WHERE id = :id AND status = 'ABERTO'";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':id' => $shiftId, ':obs' => $motivo]);
        
        if ($stmt->rowCount() > 0) {
            json(['success' => true, 'message' => 'Turno encerrado']);
        } else {
            json(['success' => false, 'message' => 'Turno não encontrado ou já fechado']);
        }
    } catch (PDOException $e) {
        json(['success' => false, 'message' => $e->getMessage()]);
    }
}

// --- RELATÓRIO DE ESCALA ---
if ($action === 'shift-get-report') {
    $patientId = $_GET['patient_id'] ?? null;
    $mesInput = $_GET['mes'] ?? date('Y-m');

    // Proteção contra string "null" ou "undefined" vinda do JS
    if (!$patientId || $patientId === 'null' || $patientId === 'undefined') { 
        json(['success' => false, 'message' => 'ID do paciente inválido ou não selecionado.']);
        exit;
    }

    // Tratamento de Data
    $ano = date('Y');
    $mes = date('m');
    
    if (!empty($mesInput) && strpos($mesInput, '-') !== false) {
        $parts = explode('-', $mesInput);
        if (count($parts) == 2) {
            $ano = intval($parts[0]); // Garante que é número
            $mes = intval($parts[1]); // Garante que é número
        }
    }

    try {
        // Query de Busca
        $sql = "
            SELECT 
                e.id,
                e.check_in,
                e.check_out,
                e.status,
                u.nickname as nome_cuidador,
                TIMESTAMPDIFF(MINUTE, e.check_in, IFNULL(e.check_out, NOW())) as minutos_trabalhados
            FROM escala e
            LEFT JOIN users u ON e.caregiver_id = u.id
            WHERE e.patient_id = :pid
            AND YEAR(e.check_in) = :ano
            AND MONTH(e.check_in) = :mes
            ORDER BY e.check_in DESC
        ";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':pid' => $patientId, 
            ':ano' => $ano, 
            ':mes' => $mes
        ]);
        
        $turnos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Agrupa totais
        $totais = [];
        foreach ($turnos as $t) {
            $nome = $t['nome_cuidador'] ?? 'Desconhecido';
            $mins = (int)$t['minutos_trabalhados'];
            if (!isset($totais[$nome])) $totais[$nome] = 0;
            $totais[$nome] += $mins;
        }

        // Formata
        $resumo = [];
        foreach ($totais as $nome => $mins) {
            $h = floor($mins / 60);
            $m = $mins % 60;
            $resumo[] = [
                'nome' => $nome,
                'total_formatado' => sprintf("%02dh %02dm", $h, $m)
            ];
        }

        // RETORNA TAMBÉM OS PARÂMETROS USADOS (PARA DEBUG)
        json([
            'success' => true, 
            'lista' => $turnos, 
            'resumo' => $resumo,
            'debug_params' => [
                'pid_recebido' => $patientId,
                'ano_filtrado' => $ano,
                'mes_filtrado' => $mes,
                'qtd_encontrada' => count($turnos)
            ]
        ]);

    } catch (PDOException $e) {
        json(['success' => false, 'message' => 'Erro SQL: ' . $e->getMessage()]);
    }
}

// --- CONTROLE DE CATETER ---
if ($action === 'get-catheters'){
    $pid = $_GET['patient_id'] ?? null;
        if (!$pid) { json(['success'=>false, 'message'=>'ID do paciente ausente']); exit; }
        
        // Busca cateteres ativos
        $stmt = $pdo->prepare("SELECT * FROM patient_catheters WHERE patient_id = :pid AND status = 'ativo' ORDER BY data_insercao DESC");
        $stmt->execute([':pid' => $pid]);
        $cateteres = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Para cada cateter, busca a última manutenção para calcular próximas datas
        foreach ($cateteres as &$cat) {
            $stmtLog = $pdo->prepare("SELECT realizado_em FROM catheter_maintenance_logs WHERE catheter_id = :cid ORDER BY realizado_em DESC LIMIT 1");
            $stmtLog->execute([':cid' => $cat['id']]);
            $last = $stmtLog->fetch(PDO::FETCH_ASSOC);
            $cat['ultima_manutencao'] = $last ? $last['realizado_em'] : $cat['data_insercao'];
        }
        
        json(['success' => true, 'data' => $cateteres]);
}

if ($action === 'save-catheter'){
    $input = json_decode(file_get_contents('php://input'), true);
        
        $sql = "INSERT INTO patient_catheters 
        (patient_id, tipo, fabricante, local_acesso, numero_lumens, calibre, comprimento, metodo_insercao, confirmacao_rx, data_insercao, intercorrencias, freq_flush, freq_curativo)
        VALUES 
        (:pid, :tipo, :fab, :loc, :lum, :cal, :comp, :met, :rx, :dt, :inter, :ff, :fc)";
        
        $stmt = $pdo->prepare($sql);
        $res = $stmt->execute([
            ':pid' => $input['patient_id'],
            ':tipo' => $input['tipo'],
            ':fab' => $input['fabricante'],
            ':loc' => $input['local_acesso'],
            ':lum' => $input['numero_lumens'],
            ':cal' => $input['calibre'],
            ':comp' => $input['comprimento'],
            ':met' => $input['metodo_insercao'],
            ':rx' => $input['confirmacao_rx'],
            ':dt' => $input['data_insercao'],
            ':inter' => $input['intercorrencias'],
            ':ff' => $input['freq_flush'],
            ':fc' => $input['freq_curativo']
        ]);
        
        json(['success' => $res]);
}

if ($action === 'remove-catheter'){
    $input = json_decode(file_get_contents('php://input'), true);
        $stmt = $pdo->prepare("UPDATE patient_catheters SET status = 'removido', data_remocao = NOW() WHERE id = :id");
        json(['success' => $stmt->execute([':id' => $input['id']])]);
}

if ($action === 'log-catheter-maintenance'){
    $input = json_decode(file_get_contents('php://input'), true);
        $stmt = $pdo->prepare("INSERT INTO catheter_maintenance_logs (catheter_id, tipo_acao, observacoes) VALUES (:cid, 'manutencao_completa', :obs)");
        json(['success' => $stmt->execute([
            ':cid' => $input['catheter_id'],
            ':obs' => $input['observacoes']
        ])]);
}

//suporte
if ($action === 'contact-support') {
    $userId = $input['userId'] ?? null;
    $subject = trim($input['subject'] ?? '');
    $messageBody = trim($input['message'] ?? '');
    
    if (!$subject || !$messageBody) {
        json(['success' => false, 'message' => 'Preencha o assunto e a mensagem.']);
    }

    // --- CONFIGURAÇÃO DO E-MAIL DE DESTINO (ADMIN) ---
    // Coloque aqui o e-mail que receberá as dúvidas dos usuários
    $emailAdmin = 'daniellllgm@gmail.com'; 

    // Tenta identificar o usuário para saber quem mandou a mensagem
    $userInfo = "Visitante (Não Logado)";
    $replyTo = $emailAdmin; // Fallback

    if ($userId) {
        $stmt = $pdo->prepare("SELECT nickname, email FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            $userInfo = "{$user['nickname']} ({$user['email']})";
            $replyTo = $user['email']; // Para você poder clicar em "Responder" no seu e-mail
        }
    }

    // Monta o e-mail para o ADMIN
    $tituloEmail = "[ACURA fale conosco] $subject";
    
    $html = "
    <div style='font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd;'>
        <h2 style='color: #2563EB;'>Nova Mensagem de Suporte</h2>
        <p><strong>Remetente:</strong> $userInfo</p>
        <p><strong>Assunto:</strong> $subject</p>
        <hr>
        <p><strong>Mensagem:</strong></p>
        <p style='background: #f9f9f9; padding: 15px; border-radius: 5px; white-space: pre-wrap;'>$messageBody</p>
        <hr>
        <p style='font-size: 12px; color: #888;'>Enviado pelo Acura Vencer Cuidando</p>
    </div>
    ";

    // Usa a função centralizada que criamos anteriormente
    // Note que enviamos PARA O ADMIN, mas colocamos o nome do usuário no corpo
    $enviou = enviarEmailSistema($emailAdmin, 'Admin Suporte', $tituloEmail, $html);

    if ($enviou) {
        // (Opcional) Enviar confirmação para o usuário também?
        // Se quiser, pode descomentar abaixo:
        
        if ($user && $user['email']) {
            enviarEmailSistema($user['email'], $user['nickname'], "Recebemos sua mensagem: $subject", 
                "Olá. Recebemos sua mensagem sobre '$subject'. Nossa equipe agradece seu contato.");
        }
        
        
        json(['success' => true, 'message' => 'Mensagem enviada.']);
    } else {
        json(['success' => false, 'message' => 'Falha técnica ao enviar e-mail.']);
    }
}

//compartilhamentos
if ($action === 'log-share') {
    $caregiverId = $input['caregiverId'] ?? null;
    $patientId = $input['patientId'] ?? null;
    $type = $input['type'] ?? 'simple'; // 'simple' ou 'full'

    if (!$caregiverId) {
        json(['success' => false, 'message' => 'ID do cuidador ausente.']);
    }

    try {
        $stmt = $pdo->prepare("
            INSERT INTO shares (caregiver_id, patient_id, share_type, created_at) 
            VALUES (:cid, :pid, :type, NOW())
        ");
        
        $stmt->execute([
            ':cid' => $caregiverId,
            ':pid' => $patientId,
            ':type' => $type
        ]);

        json(['success' => true, 'message' => 'Compartilhamento registrado!']);
    } catch (PDOException $e) {
        error_log("Erro ao logar share: " . $e->getMessage());
        json(['success' => false, 'message' => 'Erro interno ao registrar.']);
    }
    exit;
}

/* fallback */
json(['success'=>false,'message'=>'Ação inválida ou não especificada.']);


//// -- Funções de envio de e-mail

/**
 * Envia e-mails autenticados via SMTP.
 * * @param string $destinatario E-mail de destino
 * @param string $nomeDestinatario Nome do destinatário
 * @param string $assunto Assunto do e-mail
 * @param string $corpoHTML Conteúdo em HTML
 * @param string $corpoTexto Conteúdo em texto puro (fallback)
 * @return bool Retorna true se enviou, false se falhou
 */
function enviarEmailSistema($destinatario, $nomeDestinatario, $assunto, $corpoHTML, $corpoTexto = '') {
    $mail = new PHPMailer(true);

    try {
        // --- CONFIGURAÇÕES DO SERVIDOR (Preencha com dados do seu provedor/Hostinger) ---
        // $mail->SMTPDebug = SMTP::DEBUG_OFF;      // Desative o debug em produção
        $mail->isSMTP();                            // Usar SMTP
        $mail->Host       = 'smtp.hostinger.com';   // Ex: smtp.hostinger.com, smtp.gmail.com
        $mail->SMTPAuth   = true;                   // Habilitar autenticação
        $mail->Username   = 'no-reply@oncotrek.org'; // Seu e-mail de envio
        $mail->Password   = 'Cur@An@2026';    // Senha do e-mail
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // ou ENCRYPTION_STARTTLS
        $mail->Port       = 465;                    // 465 para SSL ou 587 para TLS

        // --- REMETENTE E DESTINATÁRIO ---
        $mail->setFrom('no-reply@oncotrek.org', 'Acura Vencer Cuidando');
        $mail->addAddress($destinatario, $nomeDestinatario);
        $mail->addReplyTo('lgpd@oncotrek.org', 'Acura Suporte');

        // --- CONTEÚDO ---
        $mail->isHTML(true); 
        $mail->CharSet = 'UTF-8';
        $mail->Subject = $assunto;
        $mail->Body    = $corpoHTML;
        $mail->AltBody = $corpoTexto ?: strip_tags($corpoHTML); // Texto puro para clientes sem HTML

        $mail->send();
        return true;
    } catch (Exception $e) {
        // Logar o erro no servidor, mas não exibir para o usuário final
        error_log("Erro ao enviar e-mail para $destinatario: {$mail->ErrorInfo}");
        return false;
    }
}

//gera um template bonito
function gerarTemplateEmail($titulo, $mensagem, $acaoTexto = null, $acaoLink = null) {
    $botao = '';
    if ($acaoTexto && $acaoLink) {
        $botao = "
            <div style='text-align: center; margin: 30px 0;'>
                <a href='$acaoLink' style='background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;'>
                    $acaoTexto
                </a>
            </div>
        ";
    }

    return "
    <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;'>
        <div style='background-color: #f8fafc; padding: 15px; text-align: center; border-bottom: 1px solid #e0e0e0;'>
            <h2 style='color: #333; margin: 0;'>Acura Vencer Cuidando</h2>
        </div>
        <div style='padding: 20px; color: #555; line-height: 1.6;'>
            <h3 style='color: #111;'>$titulo</h3>
            <p>$mensagem</p>
            $botao
            <p style='font-size: 12px; color: #999; margin-top: 30px;'>
                Se você não solicitou esta ação, por favor ignore este e-mail.
            </p>
        </div>
    </div>
    ";
}




