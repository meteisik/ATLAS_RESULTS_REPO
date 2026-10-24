import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_NovaMantis {

    private boolean checkNovaMantisAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteNovaMantisAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("NOVA_MANTIS_ACCOUNT_ID");
            break;
        }
        boolean authorized = checkNovaMantisAccess(data);
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        try {
            PreparedStatement novaMantisDelete = novaMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaMantisDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                novaMantisDelete.executeUpdate();
            }
        } finally {
            novaMantisConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
