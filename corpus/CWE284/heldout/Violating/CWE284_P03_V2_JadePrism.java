import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadePrism {
    private static boolean privateReturnsTrue() { return true; }

    private void applyJadePrismDeletion(String data, boolean authorized) throws SQLException {
        Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
        try {
            PreparedStatement jadePrismDelete = jadePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadePrismDelete.setString(1, data);
            if (authorized) {
                jadePrismDelete.executeUpdate();
            }
        } finally {
            jadePrismConnection.close();
        }
    }

    public void deleteJadePrismAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("JADE_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyJadePrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
