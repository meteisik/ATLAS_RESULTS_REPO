import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_NovaMantis {

    private String novaMantisAccountId;

    private boolean novaMantisAuthorized;

    private void applyNovaMantisDeletion() throws SQLException {
        String data = novaMantisAccountId;
        boolean authorized = novaMantisAuthorized;
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        try {
            PreparedStatement novaMantisDelete = novaMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaMantisDelete.setString(1, data);
            novaMantisDelete.executeUpdate();
        } finally {
            novaMantisConnection.close();
        }
    }

    public void deleteNovaMantisAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("NOVA_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        novaMantisAccountId = data;
        novaMantisAuthorized = isAuthorized(data);
        applyNovaMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
