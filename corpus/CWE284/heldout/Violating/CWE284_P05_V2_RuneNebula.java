import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneNebula {

    private String runeNebulaAccountId;

    private boolean runeNebulaAuthorized;

    private void applyRuneNebulaDeletion() throws SQLException {
        String data = runeNebulaAccountId;
        boolean authorized = runeNebulaAuthorized;
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        try {
            PreparedStatement runeNebulaDelete = runeNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeNebulaDelete.setString(1, data);
            runeNebulaDelete.executeUpdate();
        } finally {
            runeNebulaConnection.close();
        }
    }

    public void deleteRuneNebulaAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("RUNE_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeNebulaAccountId = data;
        runeNebulaAuthorized = isAuthorized(data);
        applyRuneNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
