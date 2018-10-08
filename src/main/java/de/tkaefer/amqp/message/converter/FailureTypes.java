package de.tkaefer.amqp.message.converter;

import java.util.function.Function;

import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.support.converter.MessageConversionException;

@Slf4j
public enum FailureTypes implements Function<Exception, Void> {
    STRICT(e -> {
        throw new MessageConversionException("Error while converting message.", e);
    }),
    LOG(e -> {
        log.error("Error while converting message.", e);
        return null;
    });

    private Function<Exception, Void> failureLambda;

    FailureTypes(Function<Exception, Void> failureLambda) {
        this.failureLambda = failureLambda;
    }

    @Override
    public Void apply(Exception e) {
        return failureLambda.apply(e);
    }
}
