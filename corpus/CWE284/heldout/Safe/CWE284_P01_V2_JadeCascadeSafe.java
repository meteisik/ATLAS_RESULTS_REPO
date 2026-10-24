import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeCascadeSafe {

    public void deleteJadeCascadeAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("JADE_CASCADE_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
