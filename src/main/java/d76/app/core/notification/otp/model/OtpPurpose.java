package d76.app.core.notification.otp.model;

public enum OtpPurpose {
    EMAIL_VERIFICATION {
        @Override
        public String subject() {
            return "Verify your email address";
        }

        @Override
        public String body(String otp) {
            return "Use OTP " + otp + " to verify your email.";
        }
    },

    PASSWORD_RESET {
        @Override
        public String subject() {
            return "Reset your password";
        }

        @Override
        public String body(String otp) {
            return "Use OTP " + otp + " to reset your password";
        }
    };

    public abstract String subject();

    public abstract String body(String otp);
}
