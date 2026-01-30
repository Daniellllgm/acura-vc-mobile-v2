<?php
// Exibe todos os erros na tela
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);

try {
    echo "<h1>Iniciando teste de envio...</h1>";

    // --- SUAS CONFIGURAÇÕES (Preencha com cuidado) ---
    $mail->SMTPDebug = SMTP::DEBUG_SERVER;      // Mostra o log detalhado da conversa com o servidor
    $mail->isSMTP();
    $mail->Host       = 'smtp.hostinger.com';   // Verifique se é este mesmo o host
    $mail->SMTPAuth   = true;
    $mail->Username   = 'no-reply@oncotrek.org'; // SEU EMAIL COMPLETO AQUI
    $mail->Password   = 'Cur@An@2026';         // A SENHA DO EMAIL (não do painel de controle)
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Tente ENCRYPTION_SMTPS para porta 465
    $mail->Port       = 465;                    // Use 465 (SSL) ou 587 (TLS)

    // --- REMETENTE E DESTINATÁRIO ---
    // O 'setFrom' OBRIGATORIAMENTE deve ser o mesmo e-mail do 'Username' acima
    $mail->setFrom('no-reply@oncotrek.org', 'Teste Sistema');
    
    // Coloque aqui o SEU e-mail pessoal (Gmail/Hotmail) para receber o teste
    $mail->addAddress('daniellllgm@gmail.com', 'Eu Mesmo'); 

    $mail->isHTML(true);
    $mail->Subject = 'Teste de SMTP - Debug';
    $mail->Body    = 'Se você recebeu isso, a configuração está correta! <b>Sucesso!</b>';

    $mail->send();
    echo "<h2 style='color:green'>Mensagem enviada com sucesso!</h2>";

} catch (Exception $e) {
    echo "<h2 style='color:red'>Falha ao enviar.</h2>";
    echo "<pre>Erro do Mailer: {$mail->ErrorInfo}</pre>";
}