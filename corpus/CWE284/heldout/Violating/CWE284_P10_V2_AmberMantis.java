import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberMantis {
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
        (new CWE284_P10_V2_AmberMantisSink()).applyAmberMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberMantisSink {
    public void applyAmberMantisDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberMantis.data;
        boolean authorized = CWE284_P10_V2_AmberMantis.authorized;
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            amberMantisDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberMantisConnection.close();
        }
    }
}
