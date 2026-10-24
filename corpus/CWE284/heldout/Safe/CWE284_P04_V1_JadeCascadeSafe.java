import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeCascadeSafe {

    private boolean checkJadeCascadeAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_CASCADE_ACCOUNT_ID");
        boolean authorized = checkJadeCascadeAccess(data);
        Connection jadeCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCascade");
        try {
            PreparedStatement jadeCascadeDelete = jadeCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCascadeDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
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
