package d76.app.core.service;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public interface CacheService {

    <T> void put(String key, T value, long ttl, TimeUnit timeUnit);

    <T> Optional<T> get(String key, Class<T> type);

    void evict(String key);
}
