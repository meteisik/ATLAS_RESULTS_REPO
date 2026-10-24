import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaSundialSafe {

    public void deleteNovaSundialAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_SUNDIAL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaSundialSafeChecker()).isAuthorized(data);
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        try {
            PreparedStatement novaSundialDelete = novaSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaSundialDelete.setString(1, data);
            if (authorized) {
                novaSundialDelete.executeUpdate();
            }
        } finally {
            novaSundialConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaSundialSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
