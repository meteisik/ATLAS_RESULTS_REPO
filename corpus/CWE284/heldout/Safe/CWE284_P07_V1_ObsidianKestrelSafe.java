import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianKestrelSafe {

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianKestrelSafeChecker()).isAuthorized(data);
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
}

class CWE284_P07_V1_ObsidianKestrelSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
