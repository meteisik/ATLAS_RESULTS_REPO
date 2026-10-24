import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaAuroraSafe {

    public void deleteNovaAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaAuroraSafeSink()).applyNovaAuroraDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaAuroraSafeSink {
    public void applyNovaAuroraDeletion(String data, boolean authorized) throws SQLException {
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        try {
            PreparedStatement novaAuroraDelete = novaAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaAuroraDelete.setString(1, data);
            if (authorized) {
                novaAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaAuroraConnection.close();
        }
    }
}
