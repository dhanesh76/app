package d76.app.notification.email.model;

public record MailMessage(
        String to,
        String subject,
        String content,

        MailContentType contentType
) {
}
