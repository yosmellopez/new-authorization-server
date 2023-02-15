package org.ylplabs.usersservice.service.types;

public enum DateType {
    TODAY("today"), WEEK("week"), LAST_WEEK("last-week"), MONTH("month"), LAST_MONTH("last-month"), YEAR("year"), LAST_YEAR("last-year");

    private final String type;

    DateType(String type) {
        this.type = type;
    }

    public static DateType fromString(String text) {
        if ("last-week".equalsIgnoreCase(text))
            return LAST_WEEK;
        if ("last-year".equalsIgnoreCase(text))
            return LAST_YEAR;
        if ("last-month".equalsIgnoreCase(text))
            return LAST_MONTH;
        for (DateType b : DateType.values()) {
            if (b.type.equalsIgnoreCase(text)) {
                return b;
            }
        }
        return null;
    }

    public String getType() {
        return type;
    }
}
