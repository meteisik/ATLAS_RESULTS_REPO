import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_NovaCascadeSafe {

    private String novaCascadeAccountId;

    private boolean novaCascadeAuthorized;

    private void applyNovaCascadeDeletion() throws SQLException {
        String data = novaCascadeAccountId;
        boolean authorized = novaCascadeAuthorized;
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

    public void deleteNovaCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_CASCADE_ACCOUNT_ID");
        novaCascadeAccountId = data;
        novaCascadeAuthorized = isAuthorized(data);
        applyNovaCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
