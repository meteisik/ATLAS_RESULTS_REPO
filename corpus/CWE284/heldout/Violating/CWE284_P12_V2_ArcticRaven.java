import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticRaven {
    private static int privateFive = 5;

    public void deleteArcticRavenAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticRavenBase baseObject = new CWE284_P12_V2_ArcticRavenRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticRavenBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticRavenRemover extends CWE284_P12_V2_ArcticRavenBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
        try {
            PreparedStatement arcticRavenDelete = arcticRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticRavenDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticRavenDelete.executeUpdate();
            }
        } finally {
            arcticRavenConnection.close();
        }
    }
}
