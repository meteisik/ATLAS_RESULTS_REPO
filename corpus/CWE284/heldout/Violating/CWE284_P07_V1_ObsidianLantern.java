import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianLantern {

    public void deleteObsidianLanternAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianLanternChecker()).isAuthorized(requester);
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        try {
            PreparedStatement obsidianLanternDelete = obsidianLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLanternDelete.setString(1, data);
            if (authorized) {
                obsidianLanternDelete.executeUpdate();
            }
        } finally {
            obsidianLanternConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianLanternChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
