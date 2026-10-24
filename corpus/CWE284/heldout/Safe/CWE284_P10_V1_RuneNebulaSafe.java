import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_RuneNebulaSafe {

    public static String data;

    public static boolean authorized;

    public void deleteRuneNebulaAccount() throws SQLException {
        data = System.getenv("RUNE_NEBULA_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_RuneNebulaSafeSink()).applyRuneNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_RuneNebulaSafeSink {
    public void applyRuneNebulaDeletion() throws SQLException {
        String data = CWE284_P10_V1_RuneNebulaSafe.data;
        boolean authorized = CWE284_P10_V1_RuneNebulaSafe.authorized;
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        try {
            PreparedStatement runeNebulaDelete = runeNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeNebulaDelete.setString(1, data);
            if (authorized) {
                runeNebulaDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeNebulaConnection.close();
        }
    }
}
