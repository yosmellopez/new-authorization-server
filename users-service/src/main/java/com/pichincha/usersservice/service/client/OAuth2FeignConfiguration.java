package com.pichincha.usersservice.service.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import feign.*;
import feign.codec.Decoder;
import feign.codec.ErrorDecoder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.openfeign.support.HttpMessageConverterCustomizer;
import org.springframework.cloud.openfeign.support.SpringDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import com.pichincha.usersservice.web.rest.errors.BadRequestAlertException;
import com.pichincha.usersservice.web.rest.errors.ResourceNotFoundException;
import com.pichincha.usersservice.web.rest.errors.UnauthorizedException;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.LinkedList;

import static feign.FeignException.errorStatus;

@Configuration
public class OAuth2FeignConfiguration {

    /**
     * feign OAuth2ClientContext for
     */
    private final ObjectFactory<HttpMessageConverters> messageConverters;
    //
    private final ObjectProvider<HttpMessageConverterCustomizer> customizers;
    //
    private final ObjectMapper objectMapper;

    //
    public OAuth2FeignConfiguration(ObjectFactory<HttpMessageConverters> messageConverters, ObjectProvider<HttpMessageConverterCustomizer> customizers, ObjectMapper objectMapper) {
        this.messageConverters = messageConverters;
        this.customizers = customizers;
        this.objectMapper = objectMapper;
    }

    @Bean
    public RequestInterceptor requestInterceptor() {
        return template -> template.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
    }

    @Bean
    public Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

    @Bean
    public Decoder feignDecoder() {
        return new CustomResponseEntityDecoder(new SpringDecoder(this.messageConverters, customizers));
    }


    @Bean
    public ErrorDecoder errorDecoder() {
        return new RestClientErrorDecoder(objectMapper);
    }

    static class CustomResponseEntityDecoder implements Decoder {

        private final org.slf4j.Logger log = LoggerFactory.getLogger(CustomResponseEntityDecoder.class);

        private final Decoder decoder;


        public CustomResponseEntityDecoder(Decoder decoder) {
            this.decoder = decoder;
        }

        @Override
        public Object decode(final Response response, Type type) throws IOException, FeignException {
            if (log.isDebugEnabled()) {
                log.debug("feign decode type:{}，reponse:{}", type, response.body());
            }
            if (isParameterizeHttpEntity(type)) {
                type = ((ParameterizedType) type).getActualTypeArguments()[0];
                Object decodedObject = decoder.decode(response, type);
                return createResponse(decodedObject, response);
            } else if (isHttpEntity(type)) {
                return createResponse(null, response);
            } else {
                // custom ResponseEntityDecoder if token is valid then go to errorDecoder
                if (response.status() == 401) {
                    String body = Util.toString(response.body().asReader(Util.UTF_8));
                    log.info(body);
                    clearTokenAndRetry(response, body);
                }
                return decoder.decode(response, type);
            }
        }

        /**
         * token Failure sets token to null and try again
         *
         * @param response response
         * @param body     body
         * @author maxianming
         * @date 2018/10/30 10:05
         */
        private void clearTokenAndRetry(Response response, String body) throws FeignException {
            log.error("Received Feign Request Resource Response,Response Content:{}", body);
            throw new RetryableException(
                    response.status(),
                    "access_token Expired, about to retry",
                    response.request().httpMethod(),
                    new Date(),
                    response.request());
        }

        private boolean isParameterizeHttpEntity(Type type) {
            if (type instanceof ParameterizedType) {
                return isHttpEntity(((ParameterizedType) type).getRawType());
            }
            return false;
        }

        private boolean isHttpEntity(Type type) {
            if (type instanceof Class c) {
                return HttpEntity.class.isAssignableFrom(c);
            }
            return false;
        }

        @SuppressWarnings("unchecked")
        private <T> ResponseEntity<T> createResponse(Object instance, Response response) {
            MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
            for (String key : response.headers().keySet()) {
                headers.put(key, new LinkedList<>(response.headers().get(key)));
            }
            return new ResponseEntity<>((T) instance, headers, HttpStatus.valueOf(response.status()));
        }
    }

    /**
     * Feign Customize error decoding when calling HTTP to return a response code error
     *
     * @author liudong
     * @date 2018/10/30 9:45
     */
    static class RestClientErrorDecoder implements ErrorDecoder {

        private final org.slf4j.Logger logger = LoggerFactory.getLogger(RestClientErrorDecoder.class);


        private final ObjectMapper objectMapper;

        RestClientErrorDecoder(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
        }

        @Override
        public Exception decode(String methodKey, Response response) {
            FeignException exception = errorStatus(methodKey, response);
            try {
                String bodyStr = new String(exception.responseBody().map(ByteBuffer::array).orElseGet(this::emptyArray));
                bodyStr = bodyStr.isBlank() ? "{}" : bodyStr;
                logger.error("Feign Call exception, exception methodKey:{},  response:{}", methodKey, bodyStr);
                ProblemDetail value = objectMapper.readValue(bodyStr, ProblemDetail.class);
                return switch (response.status()) {
                    case 400 -> new BadRequestAlertException(value);
                    case 404 ->
                            new ResourceNotFoundException(URI.create(methodKey), value.getTitle(), value.getDetail());
                    case 401 -> new UnauthorizedException(value);
                    default -> exception;
                };
            } catch (IOException e) {
                logger.error("Feign Call exception, exception methodKey:{}", methodKey, e);
            }
            return exception;
        }

        private byte[] emptyArray() {
            String body = "{}";
            return body.getBytes();
        }
    }

}
