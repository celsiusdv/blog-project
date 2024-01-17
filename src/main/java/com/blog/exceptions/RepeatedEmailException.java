package com.blog.exceptions;

import java.sql.SQLIntegrityConstraintViolationException;

public class RepeatedEmailException extends RuntimeException {
    public RepeatedEmailException(String message){
        super(message);
    }
}
