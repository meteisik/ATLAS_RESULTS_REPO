import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentKestrelSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSilentKestrelAccount() throws SQLException {
        data = System.getenv("SILENT_KESTREL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentKestrelSafeSink()).applySilentKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentKestrelSafeSink {
    public void applySilentKestrelDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentKestrelSafe.data;
        boolean authorized = CWE284_P10_V1_SilentKestrelSafe.authorized;
        Connection silentKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentKestrel");
        try {
            PreparedStatement silentKestrelDelete = silentKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentKestrelDelete.setString(1, data);
            if (authorized) {
                silentKestrelDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentKestrelConnection.close();
        }
    }
}
