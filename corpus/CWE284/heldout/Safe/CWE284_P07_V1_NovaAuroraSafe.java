import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaAuroraSafe {

    public void deleteNovaAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_AURORA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaAuroraSafeChecker()).isAuthorized(data);
        Connection novaAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaAurora");
        try {
            PreparedStatement novaAuroraDelete = novaAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaAuroraDelete.setString(1, data);
            if (authorized) {
                novaAuroraDelete.executeUpdate();
            }
        } finally {
            novaAuroraConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaAuroraSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
