import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeCascadeSafe {

    private String jadeCascadeAccountId;

    private boolean jadeCascadeAuthorized;

    private void applyJadeCascadeDeletion() throws SQLException {
        String data = jadeCascadeAccountId;
        boolean authorized = jadeCascadeAuthorized;
        Connection jadeCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCascade");
        try {
            PreparedStatement jadeCascadeDelete = jadeCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCascadeDelete.setString(1, data);
            if (authorized) {
                jadeCascadeDelete.executeUpdate();
            }
        } finally {
            jadeCascadeConnection.close();
        }
    }

    public void deleteJadeCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_CASCADE_ACCOUNT_ID");
        jadeCascadeAccountId = data;
        jadeCascadeAuthorized = isAuthorized(data);
        applyJadeCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
