import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaPrism {

    public void deleteNovaPrismAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_PRISM_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaPrismChecker()).isAuthorized(requester);
        Connection novaPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaPrism");
        try {
            PreparedStatement novaPrismDelete = novaPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaPrismDelete.setString(1, data);
            if (authorized) {
                novaPrismDelete.executeUpdate();
            }
        } finally {
            novaPrismConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaPrismChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
