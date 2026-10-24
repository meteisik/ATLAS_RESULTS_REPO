import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_MosaicRaven {
    private static int privateFive = 5;

    public void deleteMosaicRavenAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("MOSAIC_RAVEN_ACCOUNT_ID");
            } else {
                data = null;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
            try {
                PreparedStatement mosaicRavenDelete = mosaicRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                mosaicRavenDelete.setString(1, data);
                mosaicRavenDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                mosaicRavenConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
