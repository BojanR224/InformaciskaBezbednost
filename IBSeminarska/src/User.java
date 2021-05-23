public class User {
     String name;
     String surname;
     String ssn;

    public User(String name, String surname, String ssn) {
        this.name = name;
        this.surname = surname;
        this.ssn = ssn;
    }

    @Override
    public String toString() {
        return name+surname+ssn;
    }
}
