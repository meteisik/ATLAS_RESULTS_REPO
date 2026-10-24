import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SilentHarbor {

    public static String data;

    public static boolean authorized;

    public void deleteSilentHarborAccount() throws SQLException {
        data = System.getenv("SILENT_HARBOR_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SilentHarborSink()).applySilentHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SilentHarborSink {
    public void applySilentHarborDeletion() throws SQLException {
        String data = CWE284_P10_V1_SilentHarbor.data;
        boolean authorized = CWE284_P10_V1_SilentHarbor.authorized;
        Connection silentHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentHarbor");
        try {
            PreparedStatement silentHarborDelete = silentHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentHarborDelete.setString(1, data);
            silentHarborDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            silentHarborConnection.close();
        }
    }
}
