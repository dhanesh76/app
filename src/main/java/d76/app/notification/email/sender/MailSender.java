package d76.app.notification.email.sender;

import d76.app.notification.email.model.MailMessage;

public interface MailSender {

    void send(MailMessage message);
}
