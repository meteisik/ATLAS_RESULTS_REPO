import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeCascade {

    private void applyJadeCascadeDeletion(String data, boolean authorized) throws SQLException {
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
        if (5 == 5) {
            data = System.getenv("JADE_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyJadeCascadeDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
