import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianKestrelSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void applyObsidianKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        try {
            PreparedStatement obsidianKestrelDelete = obsidianKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianKestrelDelete.setString(1, data);
            if (authorized) {
                obsidianKestrelDelete.executeUpdate();
            }
        } finally {
            obsidianKestrelConnection.close();
        }
    }

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyObsidianKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
