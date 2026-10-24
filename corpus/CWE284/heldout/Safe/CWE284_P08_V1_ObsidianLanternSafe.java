import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianLanternSafe {

    public void deleteObsidianLanternAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianLanternSafeSink()).applyObsidianLanternDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianLanternSafeSink {
    public void applyObsidianLanternDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        try {
            PreparedStatement obsidianLanternDelete = obsidianLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLanternDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianLanternDelete.executeUpdate();
            }
        } finally {
            obsidianLanternConnection.close();
        }
    }
}
