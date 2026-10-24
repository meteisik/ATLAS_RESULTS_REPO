import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentLanternSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSilentLanternAccount() throws SQLException {
        data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentLanternSafeSink()).applySilentLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentLanternSafeSink {
    public void applySilentLanternDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentLanternSafe.data;
        boolean authorized = CWE284_P10_V1_SilentLanternSafe.authorized;
        Connection silentLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentLantern");
        try {
            PreparedStatement silentLanternDelete = silentLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentLanternDelete.setString(1, data);
            if (authorized) {
                silentLanternDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentLanternConnection.close();
        }
    }
}
