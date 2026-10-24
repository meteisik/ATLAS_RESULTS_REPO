import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentLanternSafe {
    private static boolean privateTrue = true;

    public void deleteSilentLanternAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("SILENT_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentLanternSafeSink()).applySilentLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentLanternSafeSink {
    public void applySilentLanternDeletion(String data, boolean authorized) throws SQLException {
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
