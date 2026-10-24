import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_NovaPrismSafe {

    private String novaPrismAccountId;

    private boolean novaPrismAuthorized;

    private void applyNovaPrismDeletion() throws SQLException {
        String data = novaPrismAccountId;
        boolean authorized = novaPrismAuthorized;
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
        if (5 == 5) {
            data = System.getenv("NOVA_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        novaPrismAccountId = data;
        novaPrismAuthorized = isAuthorized(data);
        applyNovaPrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
