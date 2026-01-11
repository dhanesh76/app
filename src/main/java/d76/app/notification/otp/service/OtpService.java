package d76.app.notification.otp.service;

import d76.app.core.exception.BusinessException;
import d76.app.core.service.CacheService;
import d76.app.notification.otp.exception.OtpErrorCode;
import d76.app.notification.otp.model.OtpData;
import d76.app.notification.otp.model.OtpPurpose;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class OtpService {

    private final CacheService cacheService;
    private final SecureRandom secureRandom;

    private final int otpLength;
    private final long ttlSeconds;

    public OtpService(
            CacheService cacheService,
            @Value("${otp.length}") int otpLength,
            @Value("${otp.ttl}") long ttlSeconds
    ) {
        this.cacheService = cacheService;
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
        var otpData = new OtpData(otp, otpPurpose, Instant.now());

        cacheService.put(key, otpData, ttlSeconds, TimeUnit.SECONDS);
        return otp;
    }

    public void verifyOtp(String userId, String otp, OtpPurpose otpPurpose) {
        String key = userId + ":" + otpPurpose.name();

        OtpData otpData = cacheService.get(key, OtpData.class).orElseThrow(
                () -> new BusinessException(OtpErrorCode.OTP_EXPIRED)
        );

        if (!otpPurpose.equals(otpData.purpose())) {
            log.warn("OTP validation failed user={} purpose={} expected={} reason=otp_mismatch",
                    userId, otpPurpose, otpData.purpose());

            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }

        if (!otp.equals(otpData.otp())) {
            throw new BusinessException(OtpErrorCode.INVALID_OTP);
        }
        cacheService.evict(key);
    }
}
