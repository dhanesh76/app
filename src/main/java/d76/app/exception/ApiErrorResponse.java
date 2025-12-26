package d76.app.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import java.time.Instant;
import java.util.List;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ApiErrorResponse {
    private Instant timestamp;
    private int statusCode;
    private String errorCode;
    private  String message;
    private String path;
    private List<ApiFieldError> errors;

    @Data
    @AllArgsConstructor
    public static class  ApiFieldError{
        private String field;
        private String message;
    }
}
