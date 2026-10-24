import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SilentHarbor {

    public void deleteSilentHarborAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("SILENT_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SilentHarborSink()).applySilentHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SilentHarborSink {
    public void applySilentHarborDeletion(String data, boolean authorized) throws SQLException {
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
