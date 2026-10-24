import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianCometSafe {
    private static boolean privateTrue = true;

    private boolean checkObsidianCometAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianCometAccess(data);
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianCometDelete.executeUpdate();
            }
        } finally {
            obsidianCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
