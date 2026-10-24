import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianLantern {

    public void deleteObsidianLanternAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianLanternSink()).applyObsidianLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianLanternSink {
    public void applyObsidianLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        try {
            PreparedStatement obsidianLanternDelete = obsidianLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLanternDelete.setString(1, data);
            obsidianLanternDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianLanternConnection.close();
        }
    }
}
