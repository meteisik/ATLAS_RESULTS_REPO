import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_SaffronCascadeSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String saffronCascadeAccountId;

    private boolean saffronCascadeAuthorized;

    private void applySaffronCascadeDeletion() throws SQLException {
        String data = saffronCascadeAccountId;
        boolean authorized = saffronCascadeAuthorized;
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        try {
            PreparedStatement saffronCascadeDelete = saffronCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCascadeDelete.setString(1, data);
            if (authorized) {
                saffronCascadeDelete.executeUpdate();
            }
        } finally {
            saffronCascadeConnection.close();
        }
    }

    public void deleteSaffronCascadeAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SAFFRON_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        saffronCascadeAccountId = data;
        saffronCascadeAuthorized = isAuthorized(data);
        applySaffronCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
