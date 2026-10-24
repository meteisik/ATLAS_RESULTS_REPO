import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaMantis {

    public void deleteNovaMantisAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_MANTIS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaMantisChecker()).isAuthorized(requester);
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        try {
            PreparedStatement novaMantisDelete = novaMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaMantisDelete.setString(1, data);
            if (authorized) {
                novaMantisDelete.executeUpdate();
            }
        } finally {
            novaMantisConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaMantisChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
