import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaCascadeSafe {

    public void deleteNovaCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_CASCADE_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaCascadeSafeChecker()).isAuthorized(data);
        Connection novaCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaCascade");
        try {
            PreparedStatement novaCascadeDelete = novaCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaCascadeDelete.setString(1, data);
            if (authorized) {
                novaCascadeDelete.executeUpdate();
            }
        } finally {
            novaCascadeConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaCascadeSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
