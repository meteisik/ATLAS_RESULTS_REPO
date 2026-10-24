import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CobaltRaven {
    private static int privateFive = 5;

    public void deleteCobaltRavenAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("COBALT_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CobaltRavenBase baseObject = new CWE284_P12_V2_CobaltRavenRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CobaltRavenBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CobaltRavenRemover extends CWE284_P12_V2_CobaltRavenBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
        try {
            PreparedStatement cobaltRavenDelete = cobaltRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltRavenDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                cobaltRavenDelete.executeUpdate();
            }
        } finally {
            cobaltRavenConnection.close();
        }
    }
}
