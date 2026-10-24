import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianLanternSafe {
    private static int privateFive = 5;

    private void applyObsidianLanternDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteObsidianLanternAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyObsidianLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
