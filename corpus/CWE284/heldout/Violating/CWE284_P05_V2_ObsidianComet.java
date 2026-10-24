import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianComet {
    private static int privateFive = 5;

    private String obsidianCometAccountId;

    private boolean obsidianCometAuthorized;

    private void applyObsidianCometDeletion() throws SQLException {
        String data = obsidianCometAccountId;
        boolean authorized = obsidianCometAuthorized;
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            obsidianCometDelete.executeUpdate();
        } finally {
            obsidianCometConnection.close();
        }
    }

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianCometAccountId = data;
        obsidianCometAuthorized = isAuthorized(data);
        applyObsidianCometDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
