package d76.app.core.notification.otp;

import d76.app.core.notification.otp.model.OtpData;
import org.jspecify.annotations.NullMarked;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
@NullMarked
public class OtpStore {

    //userid -> <otp, ttl>
    private final Map<String, OtpData> cache;

    public OtpStore() {
        this.cache = new ConcurrentHashMap<>();
    }

    //persist
    public void save(String key, OtpData otpData) {
        cache.put(key, otpData);
    }

    //read
    public Optional<OtpData> get(String key) {
        return Optional.ofNullable(cache.get(key));
    }

    //delete
    public void delete(String key) {
        cache.remove(key);
    }
}
