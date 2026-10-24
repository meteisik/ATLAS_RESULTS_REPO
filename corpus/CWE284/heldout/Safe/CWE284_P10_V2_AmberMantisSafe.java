import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberMantisSafe {
    private static boolean privateTrue = true;

    public static String data;

    public static boolean authorized;

    public void deleteAmberMantisAccount() throws SQLException {
        if (privateTrue) {
            data = System.getenv("AMBER_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberMantisSafeSink()).applyAmberMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberMantisSafeSink {
    public void applyAmberMantisDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberMantisSafe.data;
        boolean authorized = CWE284_P10_V2_AmberMantisSafe.authorized;
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            if (authorized) {
                amberMantisDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberMantisConnection.close();
        }
    }
}
