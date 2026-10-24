import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenMantis {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteGoldenMantisAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenMantisBase baseObject = new CWE284_P12_V2_GoldenMantisRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenMantisBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenMantisRemover extends CWE284_P12_V2_GoldenMantisBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        try {
            PreparedStatement goldenMantisDelete = goldenMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenMantisDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenMantisDelete.executeUpdate();
            }
        } finally {
            goldenMantisConnection.close();
        }
    }
}
