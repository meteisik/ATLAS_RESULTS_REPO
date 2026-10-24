import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_NovaPrismSafe {

    private void applyNovaPrismDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteNovaPrismAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("NOVA_PRISM_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyNovaPrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
