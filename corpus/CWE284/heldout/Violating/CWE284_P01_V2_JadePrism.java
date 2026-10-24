import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadePrism {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteJadePrismAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
        try {
            PreparedStatement jadePrismDelete = jadePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadePrismDelete.setString(1, data);
            jadePrismDelete.executeUpdate();
        } finally {
            jadePrismConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
