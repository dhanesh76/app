package d76.app.core.notification.otp.service;

import d76.app.core.exception.BusinessException;
import d76.app.core.notification.otp.OtpStore;
import d76.app.core.notification.otp.exception.OtpErrorCode;
import d76.app.core.notification.otp.model.OtpData;
import d76.app.core.notification.otp.model.OtpPurpose;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

@Slf4j
@Service
public class OtpService {

    private final OtpStore otpStore;
    private final SecureRandom secureRandom;

    private final int otpLength;

    private final long ttlSeconds;

    public OtpService(
            OtpStore otpStore,
            @Value("${otp.length}") int otpLength,
            @Value("${otp.ttl}") long ttlSeconds
    ) {
        this.otpStore = otpStore;
        this.otpLength = otpLength;
        this.ttlSeconds = ttlSeconds;
        this.secureRandom = new SecureRandom();
    }

    private String generateOtp() {
        int range = (int) Math.pow(10, otpLength);

        int otp = secureRandom.nextInt(range);
        return String.format("%0" + otpLength + "d", otp);
    }

    public String issueOtp(String userId, OtpPurpose otpPurpose) {
        String key = userId + ":" + otpPurpose.name();

        String otp = generateOtp();
        var otpData = new OtpData(otp, ttlSeconds, otpPurpose, Instant.now());

        otpStore.save(key, otpData);
        return otp;
    }

    public void verifyOtp(String userId, String otp, OtpPurpose otpPurpose) {
        String key = userId + ":" + otpPurpose.name();

        OtpData otpData = otpStore.get(key).orElseThrow(
                () -> new BusinessException(OtpErrorCode.OTP_EXPIRED)
        );

        //check ttl
        var issuedAt = otpData.issuedAt();
        var age = Duration.between(issuedAt, Instant.now()).getSeconds();

        if (age > otpData.ttl()) {
            otpStore.delete(key);
            throw new BusinessException(OtpErrorCode.OTP_EXPIRED);
        }

        if (!otpPurpose.equals(otpData.purpose())) {

            log.warn("OTP validation failed user={} purpose={} expected={} reason=otp_mismatch",
                    userId, otpPurpose, otpData.purpose());

            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }

        if (!otp.equals(otpData.otp())) {
            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }

        otpStore.delete(key);
    }
}
